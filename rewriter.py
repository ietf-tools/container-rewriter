#!/usr/bin/env python3
import email.errors
import email.utils
import logging
import os
import re
import threading
from email.header import Header, decode_header, make_header
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import TimedRotatingFileHandler

import checkdmarc
import dkim2hop
import Milter
import psycopg
from expiringdict import ExpiringDict
from psycopg_pool import ConnectionPool

forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
local_domains = os.environ.get("LOCAL_DOMAINS", forwarding_domain)
rewrite_domains = os.environ.get("REWRITE_DOMAINS", "map[mydomain.com:dmarc.mydomain.com]")

def parse_ignore_list(value):
    # comma separated; entries are trimmed and matched case-insensitively
    return {x.strip().lower() for x in value.split(',') if x.strip()}

ignore_list = parse_ignore_list(os.environ.get("IGNORELIST", "alldanes@lists.sys.slush.ca"))
# Postfix's recipient_delimiter: user+ext@domain is looked up as itself,
# then as user@domain
recipient_delimiter = os.environ.get("RECIPIENT_DELIMITER", "+")
mailman_sasl_user = os.environ.get("MAILMAN_SASL_USER", "mailman@ietf.org").lower()

# DKIM2 (draft-ietf-dkim-dkim2-spec-09), off unless configured.
# DKIM2_KEYDIR: sign mail relayed off-site, with the key in
#   <DKIM2_KEYDIR>/<signing domain>/<DKIM2_SELECTOR>.key; the signing domain
#   is the envelope sender's domain or the nearest parent with a directory.
#   Without DKIM2_SELECTOR the newest key in the directory is used.
# DKIM2_AUTHSERV_ID: verify the DKIM2 chain on mail arriving from outside
#   and report it in an Authentication-Results field under this name.
dkim2_keydir = os.environ.get("DKIM2_KEYDIR", "")
dkim2_selector = os.environ.get("DKIM2_SELECTOR", "")
dkim2_authserv_id = os.environ.get("DKIM2_AUTHSERV_ID", "")
# DKIM2_SIGN_DAEMON: split then sign.  Postfix sends each off-site copy,
#   one recipient at a time, back through a loopback listener whose
#   milter_macro_daemon_name is this; mail is signed there and only there.
#   Every other listener rewrites and records, and never signs.  Unset,
#   mail is signed in the transaction that relays it off-site
dkim2_sign_daemon = os.environ.get("DKIM2_SIGN_DAEMON", "")
# LIST_VERP: in the signing pass (DKIM2_SIGN_DAEMON), give each list copy
#   an envelope sender in mailman's VERP format, <list>-bounces+<local>=
#   <domain>@, so a bounce names the subscriber it is for
list_verp = os.environ.get("LIST_VERP", "").lower() in ("1", "yes", "true", "on")


def alias_dkim2_setting(value):
    return (value or "").strip().lower() in ("yes", "true", "1", "on")


# ALIAS_DKIM2: let an alias forward (or a reply to a wrapped address) take
#   the DKIM2 path instead of the DMARC rule's From: when the message came
#   with a DKIM2 chain that verified and our signature can extend it (our
#   forwarding domain matches the alias's, and we hold its key), From is
#   kept and only the envelope becomes FORWARDING_ADDR.  Off by default.
#   For an alias address it needs DKIM2_SIGN_DAEMON: in a single pass the
#   rewriter never sees the off-site copy Postfix makes
alias_dkim2 = alias_dkim2_setting(os.environ.get("ALIAS_DKIM2"))
# where keys are looked up: None is the DNS; the tests give a table
dkim2_dns = None
# how the chain a message arrived with checked out, carried through mailman
# to the fan-out; set here on arrival, and never taken from outside
DKIM2_ARRIVAL = "X-DKIM2-Arrival"
DKIM2_NOT_VERIFIED = ("fail", "permerror", "temperror")
# a list's fan-out, marked for the signing pass, which removes it; X- fields
# are not hashed by DKIM2, so neither changes a signature
DKIM2_EXPLODED = "X-DKIM2-Exploded"
# the fields that make up a DKIM2 chain
DKIM2_CHAIN_FIELDS = ("dkim2-signature", "message-instance")

_policy_cache = ExpiringDict(max_len=50000, max_age_seconds=1800)

rewrite_domain_map = {
    x.split(":")[0]: x.split(":")[1] for x in rewrite_domains[4:-1].split(" ")
}

rewrite_domain_reverse_map = dict(map(reversed,rewrite_domain_map.items()))

milter_listening_port = os.environ.get("LISTENING_PORT", "8800")
http_listening_port = os.environ.get("HTTP_LISTENING_PORT", "8000")
log_level = os.environ.get("LOG_LEVEL", "INFO")
logging_procname = os.environ.get("LOGGING_PROCNAME", "milter/rewriter")
logging_filename = os.environ.get("LOGGING_FILENAME", "/var/log/rewrite.log")
logging_rotate_period = os.environ.get("LOGGING_ROTATE_PERIOD", "D")
logging_format = "{asctime} milter/rewriter[{process}]: {message} [{filename}:{lineno}]"

# matched against the unquoted (internal) form of the address, whose local
# part may itself contain @; the original domain may be UTF-8 (SMTPUTF8)
# (list bounces are excluded by is_wrapped())
wrapped_regex = rf"^.+=40[-a-z0-9.\x80-\U0010ffff]+@{re.escape(forwarding_domain)}$"
wrapped_mailmatch = re.compile(wrapped_regex, re.IGNORECASE)

# Mailman 3 bounce addresses: <list>-bounces@, VERP <list>-bounces+<user>=<domain>@
# and probes <list>-bounces+<token>@; any of them may also be wrapped by us
# (<list>-bounces=40<domain>@, <list>-bounces+<user>=<domain>=40<domain>@)
listbounce_regex = r"^[^@+]+-bounces(?:\+[^@]*|=40[^@]*)?@"
listbounce_mailmatch = re.compile(listbounce_regex, re.IGNORECASE)

logging.basicConfig(
    level=log_level,
    style="{",
    datefmt="%b %d %H:%M:%S",
    format=logging_format
)

logger = logging.getLogger(__name__)
logger.setLevel(log_level)
file_handler = TimedRotatingFileHandler(
    logging_filename, when=logging_rotate_period, interval=1, backupCount=5
)

file_formatter = logging.Formatter(
    style="{",
    datefmt="%b %d %H:%M:%S",
    fmt=logging_format,
)

file_handler.setFormatter(file_formatter)

logger.addHandler(file_handler)
logging = logging.LoggerAdapter(logger)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if self.path != "/healthz":
            log_line = format % args
            logging.info(f"{log_line} [{self}]")

    def do_GET(self):
        if self.path == "/healthz":
            try:
                with get_db_pool().connection() as conn, conn.cursor() as cur:

                    cur.execute("SELECT email from virtual LIMIT 1")
                    cur.fetchall()
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    try:
                        self.wfile.write(b"OK")
                    except BrokenPipeError as e:
                        logging.debug(f"Client timeout: {e}")
            except psycopg.OperationalError:
                self.send_response(503)
                # Set the response headers
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                # Write the response content
                self.wfile.write(b"Not OK")
        elif self.path == "/livez":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            # Set the response headers
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            # Write the response content
            self.wfile.write(b"Not OK")


_db_pool = None
_db_pool_lock = threading.Lock()
def get_db_pool() -> ConnectionPool:
    # each milter connection runs in its own thread; without the lock two
    # first messages could each build a pool, and one would leak
    global _db_pool
    if _db_pool is None:
        with _db_pool_lock:
            if _db_pool is None:
                _db_pool = ConnectionPool(
                    kwargs={
                        "dbname": os.getenv("DB_NAME", "postfix"),
                        "host": os.getenv("DB_HOST", "localhost"),
                        "user": os.getenv("DB_USER", "postgres"),
                        "password": os.getenv("DB_PASSWORD", "postgres"),
                        "port": os.getenv("DB_PORT", "5432"),
                    },
                    check=ConnectionPool.check_connection,
                    open=True,
                    timeout=5,
                )
    return _db_pool


def lookup_keys(key):
    # the keys Postfix tries for an address, in order: user+ext@domain, then
    # user@domain; the extension starts at the first delimiter character
    local, at, domain = key.rpartition('@')
    for i, ch in enumerate(local):
        if ch in recipient_delimiter:
            return [key, f"{local[:i]}{at}{domain}"]
    return [key]

def is_ignored(key):
    # an ignore list entry also covers its +extension addresses
    return any(k in ignore_list for k in lookup_keys(key))

def test_virtual_alias(email_addr):
    # alias+ext@domain is expanded through alias@domain, as Postfix does
    keys = [k for addr in email_addr for k in lookup_keys(addr)]
    with get_db_pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT email from virtual where email = ANY(%s)", [keys])
        return len(cur.fetchall()) > 0

def _dns_temporary_failure(status):
    # a timeout ("... timed out", or "The resolution lifetime expired ..."
    # when the overall lifetime runs out) or a SERVFAIL ("All nameservers
    # failed to answer the query ...: Server ... answered SERVFAIL") says
    # nothing about the domain's policy, so it must not be cached
    error = (status.get("error") or "").lower()
    return any(s in error for s in ("timed out", "lifetime expired", "servfail"))

def _check_dmarc_uncached(domain):
    matches = ["reject", "quarantine"]
    dmarc_status = checkdmarc.check_dmarc(domain, timeout=1.0, timeout_retries=2)
    logging.debug(f"dmarc status is {dmarc_status}")
    if "tags" in dmarc_status:
        # a record found on a parent (organisational) domain governs this
        # domain as a subdomain, so sp= applies; checkdmarc defaults sp to p
        location = (dmarc_status.get("location") or domain).rstrip(".").lower()
        tag = "p" if location == domain else "sp"
        return dmarc_status["tags"][tag]["value"] in matches
    if _dns_temporary_failure(dmarc_status):
        return None
    return False

def _check_spf_uncached(domain):
    matches = ["softfail", "fail"]
    spf_status = checkdmarc.check_spf(domain, timeout=1.0, timeout_retries=2)
    logging.debug(f"spf status is {spf_status}")
    if "parsed" in spf_status:
        return any(x in spf_status["parsed"]["all"] for x in matches)
    if _dns_temporary_failure(spf_status):
        return None
    return False

def _cached(kind, fn, email_addr):
    domain = email_addr.rsplit("@")[-1].lower()
    key = (kind, domain)
    result = _policy_cache.get(key)
    if result is None:
        result = fn(domain)
        if result is not None:
            _policy_cache[key] = result
    return bool(result)

def check_dmarc(email_addr):
    return _cached("dmarc", _check_dmarc_uncached, email_addr)

def check_spf(email_addr):
    return _cached("spf", _check_spf_uncached, email_addr)

def format_from_header(name, addr):
    # parseaddr() hands back the raw display name: it may be RFC 2047
    # encoded, raw UTF-8, or contain quotes.  Decode it to text and
    # re-quote or re-encode it as needed.
    if not name:
        return addr
    try:
        display = str(make_header(decode_header(name)))
    except (email.errors.HeaderParseError, LookupError, UnicodeDecodeError):
        display = name
    # CR/LF (e.g. from an encoded-word) would start a new header line
    display = " ".join(re.sub(r"[\x00-\x1f\x7f]", " ", display).split())
    if not display:
        return addr
    if not addr.isascii():
        # SMTPUTF8 message: RFC 6532 allows a raw UTF-8 display name
        if re.search(r'[][\\()<>@,:;".]', display):
            display = '"' + display.replace('\\', '\\\\').replace('"', '\\"') + '"'
        return f"{display} <{addr}>"
    if display.isascii():
        return email.utils.formataddr((display, addr))
    # RFC 2047: encoded-words of at most 75 characters, separated by spaces
    encoded = Header(display, "utf-8", maxlinelen=75).encode(linesep="\n")
    return " ".join(encoded.split()) + f" <{addr}>"

_atom = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~\x80-\U0010ffff-]+")

def unquote_local(local):
    if len(local) >= 2 and local[0] == local[-1] == '"':
        return re.sub(r'\\(.)', r'\1', local[1:-1])
    return local

def quote_local(local):
    # RFC 5321/5322: a local part that is not a dot-atom must be quoted
    if local and all(_atom.fullmatch(p) for p in local.split('.')):
        return local
    return '"' + local.replace('\\', '\\\\').replace('"', '\\"') + '"'

def internal_addr(addr):
    # Postfix's internal (unquoted) form, as used for virtual table lookups
    local, _, domain = addr.rpartition('@')
    return f"{unquote_local(local)}@{domain}".lower()

def wrap_addr(addr, new_domain):
    local, _, domain = addr.rpartition('@')
    return f"{quote_local(unquote_local(local) + '=40' + domain.lower())}@{new_domain}"

def unwrap_addr(addr):
    local, _, _ = addr.rpartition('@')
    user, sep, orig_domain = unquote_local(local).rpartition('=40')
    return f"{quote_local(user)}@{orig_domain}" if sep else addr

def unwrap_header_addrs(value, wrapped=None):
    # an address-list header (To:, Cc:) with our wrapped addresses unwrapped,
    # or None if it has none; display names are kept.  wrapped says which
    # addresses are ours to unwrap (default: is_wrapped)
    wrapped = wrapped or is_wrapped
    pairs = [(name, addr) for name, addr in email.utils.getaddresses([value]) if addr]
    if not any(wrapped(addr) for _name, addr in pairs):
        return None
    addrs = [format_from_header(name, unwrap_addr(addr) if wrapped(addr) else addr)
             for name, addr in pairs]
    # RFC 5322 2.1.1: fold between addresses to keep lines short
    lines = [addrs[0]]
    for addr in addrs[1:]:
        if len(lines[-1]) + len(addr) + 2 > 76:
            lines.append(addr)
        else:
            lines[-1] += ", " + addr
    return ",\n\t".join(lines)

def valid_wraps(addrs):
    # the wrapped addresses we handed out in the last 30 days.  Recipients
    # added with addrcpt() skip Postfix's RCPT checks, so only these may be
    # delivered to, or a Cc: list would turn us into an open relay
    if not addrs:
        return set()
    with get_db_pool().connection() as conn, conn.cursor() as cur:
        cur.execute("""
                    SELECT email FROM virtual
                    WHERE email = ANY(%s) AND updated >= NOW() - INTERVAL '30 DAYS';
                    """, ([internal_addr(a) for a in addrs],))
        return {row[0] for row in cur.fetchall()}

def is_wrapped(addr):
    # list bounces are wrapped too, but unwrap_list_bounces() handles those
    key = internal_addr(addr)
    return bool(wrapped_mailmatch.search(key)) and not listbounce_mailmatch.search(key)

def looks_like_wrapped_list_bounce(addr):
    # the shape of a wrapped list bounce, whatever list it names:
    # list-bounces[+sub=domain]=40list.domain@dmarc.domain
    if not listbounce_mailmatch.search(addr):
        return False
    local, _, domain = internal_addr(addr).rpartition('@')
    return domain in rewrite_domain_reverse_map and '=40' in local

def is_wrapped_list_bounce(addr):
    # a list's -bounces address (VERP or not) wrapped by us on the way out.
    # It is restored with addrcpt(), past Postfix's RCPT checks and with no
    # record of the wrap, so only one of our own lists counts (as in
    # verp_sender()); anything else would relay to <x-bounces@any.domain>
    return looks_like_wrapped_list_bounce(addr) and check_local(unwrap_addr(addr))

# a recipient that needs no quoting and reads back the same from mailman's
# verp_regexp: no "=" in the local part, an ASCII domain
_verp_local = re.compile(r"[A-Za-z0-9!#$%&'*+/?^_`{|}~.-]+")
_verp_domain = re.compile(r"[A-Za-z0-9.-]+")

def verp_sender(env_from, rcpt):
    # mailman's verp_format, ${bounces}+${local}=${domain}, for a list's
    # plain -bounces sender (wrapped by us or not); None if this is not one,
    # or the recipient would not parse back out of it (mailman's
    # verp_regexp takes the local part up to the first "=").  Only our own
    # lists: another organisation's list post, forwarded through one of
    # our aliases, keeps its sender
    local, _, domain = env_from.rpartition('@')
    bounces, wrap, list_domain = unquote_local(local).partition('=40')
    if not re.fullmatch(r"[^@+=]+-bounces", bounces, re.IGNORECASE):
        return None
    if wrap:
        if domain.lower() not in rewrite_domain_reverse_map or not check_local(list_domain):
            return None
    elif not check_local(domain):
        return None
    rlocal, _, rdomain = rcpt.rpartition('@')
    if not (_verp_local.fullmatch(rlocal) and _verp_domain.fullmatch(rdomain)):
        return None
    if wrap:
        return wrap_addr(f"{bounces}+{rlocal}={rdomain}@{list_domain}", domain)
    return f"{bounces}+{rlocal}={rdomain}@{domain}"

def check_local(email_addr):
    local_domain_list = local_domains.split(" ")
    domain = email_addr.rsplit("@")[-1].lower()
    return domain in local_domain_list

def update_addr_wrap_log(email_addr, new_email_addr):
    update_addr_wrap_log = """
    INSERT INTO virtual (email, destination, transport, source)
    VALUES (%s, %s, 'relay:', 'rewriter')
    ON CONFLICT (email) DO
    UPDATE SET updated = now();
    """
    try:
        with get_db_pool().connection() as conn, conn.cursor() as cur:
            cur.execute(update_addr_wrap_log, (internal_addr(new_email_addr), internal_addr(email_addr),))
    except psycopg.OperationalError as e:
        logging.info(f"failed to update addr_wrap_log: {e}")
    return True

class EnvelopeMilter(Milter.Base):
    def __init__(self):
        self.id = Milter.uniqueID()
        self.mail_to = []
        self.mail_from = None
        self.header_from = None
        self.header_to = None
        self.addr_headers = []
        self.fields = []
        self.seen = None
        self.header_changes = []
        self.env_from_out = None
        self.dkim2_arrival_status = None
        self.dkim2_off = False
        self.dkim2_signing = False
        self.exploded_marks = 0
        self.dkim2_chain_fields = {}
        self.addr_headers_unwrapped = False

    def envfrom(self, f, *str):
        # one milter instance serves every message on an SMTP connection
        self.mail_to = []
        self.header_from = None
        self.header_to = None
        self.addr_headers = []
        self.dkim2_abandon()
        self.fields = []
        self.seen = None
        self.header_changes = []
        self.env_from_out = None
        self.dkim2_arrival_status = None
        self.dkim2_off = False
        self.exploded_marks = 0
        self.dkim2_chain_fields = {}
        self.addr_headers_unwrapped = False
        # {daemon_name} is a connect macro, so it holds for every message
        # on the connection; a listener that does not name itself never signs
        self.dkim2_signing = bool(dkim2_sign_daemon) and (
            self.getsymval('{daemon_name}') == dkim2_sign_daemon)
        # addresses keep their case: local parts (SRS, VERP) can be case
        # sensitive and delrcpt() must name the recipient exactly as given;
        # internal_addr() gives the lowercased form for comparisons
        self.mail_from = f
        return Milter.CONTINUE

    def envrcpt(self, to, *str):
        addr = email.utils.parseaddr(to)[1]
        if not is_wrapped(addr) and is_wrapped(lookup_keys(internal_addr(addr))[-1]):
            # Postfix would deliver wrap+ext@ through the wrap's row, past
            # the check below (and its expiry); nobody needs one
            logging.info(f"reject: {addr} is a wrapped address with an extension [{self.id}]")
            self.setreply("550", "5.1.1", "unknown wrapped address")
            return Milter.REJECT
        if looks_like_wrapped_list_bounce(addr) and not is_wrapped_list_bounce(addr):
            # we only wrap our own lists' bounce addresses
            logging.info(f"reject: {addr} is not a wrapped bounce address of one of our lists [{self.id}]")
            self.setreply("550", "5.1.1", "unknown wrapped address")
            return Milter.REJECT
        if is_wrapped(addr):
            # check the wrap here, not after DATA: refusing one RCPT makes
            # the sender bounce just that address, while dropping it after
            # we have accepted the message would lose it (RFC 5321 6.1)
            try:
                valid = internal_addr(addr) in valid_wraps([addr])
            except psycopg.OperationalError as e:
                logging.info(f"none: wrap lookup for {addr} failed: {e} [{self.id}]")
                self.setreply("451", "4.3.0", "backend unavailable")
                return Milter.TEMPFAIL
            except Exception:
                logging.exception(f"error: wrap lookup for {addr} failed [{self.id}]")
                self.setreply("451", "4.3.0", "rewriter internal error")
                return Milter.TEMPFAIL
            if not valid:
                logging.info(f"reject: {addr} has no current wrap record [{self.id}]")
                self.setreply("550", "5.1.1", "unknown wrapped address")
                return Milter.REJECT
        self.mail_to.append(addr)
        return Milter.CONTINUE

    def rcpt_keys(self):
        # recipients as the lowercased, unquoted keys used in the database
        return [internal_addr(addr) for addr in self.mail_to]

    def offsite_rcpts(self):
        # recipients we relay straight off-site, which need a From that
        # passes DMARC; ignored recipients are left to Postfix, whose
        # transport for them restores the original From
        return [a for a in self.rcpt_keys() if not check_local(a) and not is_ignored(a)]

    def header(self, name, value):
        if name.lower() == "from":
            self.header_from = value
        if name.lower() == "to":
            self.header_to = value
        if name.lower() in ("to", "cc"):
            self.addr_headers.append((name, value))
        if name.lower() == DKIM2_EXPLODED.lower():
            self.exploded_marks += 1
        if name.lower() in DKIM2_CHAIN_FIELDS:
            self.dkim2_chain_fields[name] = self.dkim2_chain_fields.get(name, 0) + 1
        if (dkim2_keydir or dkim2_authserv_id) and not self.dkim2_off:
            try:
                self.fields.append(dkim2hop.header_field(name, value))
            except Exception:
                self.dkim2_give_up("header")
        return Milter.CONTINUE

    def dkim2_arriving(self):
        # mail from outside, whose chain we verify against its envelope.
        # The signing pass only ever gets mail that has been through us
        return (bool(dkim2_authserv_id) and not self.dkim2_signing
                and not self.getsymval('{auth_authen}'))

    def dkim2_may_sign(self):
        # will the body's hash be wanted?  It is if we may sign (only mail
        # we relay off-site is; unwrapping does not change this, a wrapped
        # recipient is already an off-site one) or may have a header change
        # to record: those are made for off-site recipients and for aliases
        if self.dkim2_signing or self.offsite_rcpts():
            return True
        return test_virtual_alias([k for k in self.rcpt_keys() if not is_ignored(k)])

    def dkim2_abandon(self):
        # a message that never reached eom() (the client gave up, or sent
        # RSET) may have key lookups queued: drop them
        seen, self.seen = self.seen, None
        if seen is not None:
            try:
                seen.abandon()
            except Exception:
                pass

    def abort(self):
        self.dkim2_abandon()
        return Milter.CONTINUE

    def close(self):
        self.dkim2_abandon()
        return Milter.CONTINUE

    def dkim2_give_up(self, where):
        # DKIM2 must never be the reason mail is not delivered: whatever
        # goes wrong in it, this message carries on without it -- no
        # verdict, no signature -- exactly as if DKIM2 were not configured
        queue_id = self.getsymval('i') or '-'
        logging.exception(f"{queue_id} dkim2: error in {where}, carrying on without DKIM2 [{self.id}]")
        self.dkim2_off = True
        self.seen = None

    def eoh(self):
        # the header fields are all here: from now on the body is hashed and
        # the DKIM2 chain verified as the body arrives, and never kept
        if (dkim2_keydir or dkim2_authserv_id) and not self.dkim2_off:
            try:
                self.dkim2_seen()
            except Exception:
                self.dkim2_give_up("eoh")
        return Milter.CONTINUE

    def body(self, chunk):
        if self.seen is not None:
            try:
                self.seen.feed(chunk)
            except Exception:
                self.dkim2_give_up("body")
        return Milter.CONTINUE

    def change_header(self, name, idx, value):
        # chgheader(), remembered so the DKIM2 Message-Instance can record
        # what the header field was before (idx counts from 1; 0 is the first)
        self.chgheader(name, idx, value)
        self.header_changes.append((name, max(idx, 1), value))

    def fields_after_changes(self):
        fields = list(self.fields)
        for name, idx, value in self.header_changes:
            seen = 0
            for i, field in enumerate(fields):
                if dkim2hop._name(field) == name.lower().encode():
                    seen += 1
                    if seen == idx:
                        fields[i] = dkim2hop.header_field(name, value)
                        break
        return fields

    def change_env_from(self, env_from_addr, new_addr, queue_id):
        # RFC 5321 4.5.5: a null sender (bounce, DSN) must stay null so a
        # failed delivery can't bounce back to us and loop
        if not env_from_addr:
            logging.info(f"{queue_id} none: null Envelope-From kept, not changed to {new_addr} [{self.id}]")
            return env_from_addr
        self.chgfrom(new_addr)
        self.env_from_out = new_addr
        return new_addr

    def log_envelope_wrap(self, env_from_addr, new_env_from):
        # bounces come back to the wrapped envelope sender, and envrcpt()
        # only accepts wraps it has a record for.  A null sender stays
        # null, and unwrap_list_bounces() restores a wrapped list bounce
        if new_env_from != env_from_addr and is_wrapped(new_env_from):
            update_addr_wrap_log(env_from_addr, new_env_from)

    def change_header_from(self, name, new_addr):
        # keep the original From, as postconfirm did, so it isn't lost
        self.change_header("From", 0, format_from_header(name, new_addr))
        self.addheader("X-Original-From", self.header_from)

    def unwrap_list_bounces(self, queue_id):
        # a -bounces recipient in a rewrite domain was wrapped by us on the
        # way out (list-bounces=40list.domain@dmarc.domain); restore it
        for i, addr in enumerate(self.mail_to):
            if not listbounce_mailmatch.search(addr):
                continue
            if not is_wrapped_list_bounce(addr):
                logging.info(f"{queue_id} none: list bounce already unwrapped {addr} [{self.id}]")
                continue
            unwrapped_addr = unwrap_addr(addr)
            logging.info(f"{queue_id} unwrap: list bounce unwrapped from {addr} to {unwrapped_addr} [{self.id}]")
            self.delrcpt(addr)
            self.addrcpt(f"<{unwrapped_addr}>")
            self.mail_to[i] = unwrapped_addr
            self.unwrap_addr_headers(queue_id)

    def unwrap_from_headers(self, queue_id):
        # the wrapped envelope recipients are delivered to their original
        # addresses, and our wraps in To:/Cc: are shown unwrapped.  A wrap
        # found only in the headers is not added as a recipient: the
        # sender's server already gave us every wrap it meant to deliver
        # to, and adding them would let one RCPT fan out to any number of
        # harvested wraps, past Postfix's recipient checks and limits.
        # Returns the unwrapped recipients it added

        # envelope wraps were checked in envrcpt(), so all of them are valid
        envelope_wraps = [a for a in self.mail_to if is_wrapped(a)]
        keep = [a for a in self.mail_to if not is_wrapped(a)]
        seen = {internal_addr(a) for a in keep}
        added = []
        for addr in envelope_wraps:
            unwrapped = unwrap_addr(addr)
            if internal_addr(unwrapped) in seen:
                continue
            seen.add(internal_addr(unwrapped))
            added.append(unwrapped)

        # delrcpt() must name the recipient exactly as it was given
        for addr in envelope_wraps:
            self.delrcpt(addr)
            logging.info(f"{queue_id} unwrap: envelope recipient {addr} unwrapped [{self.id}]")
        for addr in added:
            self.addrcpt(f"<{addr}>")
            logging.info(f"{queue_id} unwrap: recipient {addr} added [{self.id}]")
        self.mail_to = keep + added

        self.unwrap_addr_headers(queue_id)
        return added

    def unwrap_addr_headers(self, queue_id):
        # our wraps in To:/Cc: shown unwrapped: a person's, and a list's
        # -bounces address, which a bounce carries in To: and mailman reads
        # its VERP from.  Once per message: each header is changed from its
        # value as it arrived
        if self.addr_headers_unwrapped:
            return
        self.addr_headers_unwrapped = True
        def ours(addr):
            return is_wrapped(addr) or is_wrapped_list_bounce(addr)
        # chgheader() counts from 1 among headers of the same name
        counts = {}
        for name, value in self.addr_headers:
            idx = counts[name.lower()] = counts.get(name.lower(), 0) + 1
            new_value = unwrap_header_addrs(value, ours)
            if new_value is not None:
                self.change_header(name, idx, new_value)
                logging.info(f"{queue_id} unwrap: header-{name} changed from {value} to {new_value} [{self.id}]")

    def rewrite_forwarded(self, hdr_from_name, hdr_from_addr, env_from_addr, queue_id):
        # a message we pass on from someone else's domain (alias forward,
        # reply to a wrapped address): take over a p=reject/quarantine From,
        # or just the envelope when only SPF would fail
        if self.dkim2_alias_path(env_from_addr):
            # our signature will extend the sender's chain: From stays the
            # author's, and only the envelope (our mf=) becomes ours
            logging.debug(f"{queue_id} debug: on the DKIM2 path, From not rewritten for DMARC [{self.id}]")
            logging.info(
                f"{queue_id} rewrite-envelope: SPF only, Header-From: {hdr_from_addr} "
                f"Envelope-From: {env_from_addr or '<>'} [{self.id}]"
            )
            self.change_env_from(env_from_addr, forwarding_addr, queue_id)
        elif check_dmarc(hdr_from_addr):
            new_hdr_from_addr = wrap_addr(hdr_from_addr, forwarding_domain)
            # nobody replies to a bounce, so no wrap entry for it
            if env_from_addr:
                update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
            new_env_from = self.change_env_from(env_from_addr, forwarding_addr, queue_id)
            self.change_header_from(hdr_from_name, new_hdr_from_addr)
            logging.info(
                f"{queue_id} rewrite-both: Envelope-From changed from {env_from_addr or '<>'} to {new_env_from or '<>'}, header-from changed {hdr_from_addr} to {new_hdr_from_addr} [{self.id}]"
            )
        # SPF is checked on the MAIL FROM domain; we already send for
        # our local domains, so forwarding can't break theirs
        elif env_from_addr and not check_local(env_from_addr) and check_spf(env_from_addr):
            logging.info(
                f"{queue_id} rewrite-envelope: SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr or '<>'} [{self.id}]"
            )
            self.change_env_from(env_from_addr, forwarding_addr, queue_id)
        else:
            logging.info(
                f"{queue_id} none: No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr} [{self.id}]"
            )

    def dkim2_seen(self):
        # a message with no body never reaches body(), and one with no
        # header fields at all not even eoh()
        if self.seen is None:
            self.seen = dkim2hop.Stream(self.fields, self.mail_from, self.mail_to,
                                        dkim2_dns, arriving=self.dkim2_arriving(),
                                        may_sign=self.dkim2_may_sign())
        return self.seen

    def dkim2_verify_arrival(self, queue_id):
        # mail from outside: the DKIM2 chain it came with was checked against
        # the envelope it came in as it arrived; say how that went.  Report
        # only: nothing is refused here, but a chain that did not verify is
        # not signed on the way out
        if self.dkim2_off or not self.dkim2_arriving():
            return None
        try:
            result = self.dkim2_seen().result()
            report = dkim2hop.authentication_results(result, dkim2_authserv_id)
        except Exception:
            self.dkim2_give_up("verification")
            return None
        logging.info(f"{queue_id} dkim2: arrival {result.status}: "
                     f"{dkim2hop.clean(result.message)} [{self.id}]")
        # only we may say how a message arrived
        stale = sum(1 for f in self.fields if dkim2hop._name(f) == DKIM2_ARRIVAL.lower().encode())
        for idx in range(stale, 0, -1):
            self.chgheader(DKIM2_ARRIVAL, idx, None)
        self.addheader(DKIM2_ARRIVAL, result.status)
        self.addheader("Authentication-Results", report, 0)
        return result.status

    def dkim2_arrival(self, verified):
        # this transaction's verdict, else the one we attached on arrival
        # (it comes back to us from mailman, which we trust to relay it)
        if verified is not None:
            return verified
        if not self.getsymval('{auth_authen}'):
            return None
        return self.dkim2_arrival_field()

    def dkim2_arrival_field(self):
        for field in self.fields:
            if dkim2hop._name(field) == DKIM2_ARRIVAL.lower().encode():
                return dkim2hop.clean(field.split(b":", 1)[1].decode("ascii", "replace"), 20).lower()
        return None

    def dkim2_list_path(self, env_from_addr, list_fanout):
        # will DKIM2 answer for this list copy?  Mailman recorded what it
        # changed, we hold a key for the envelope domain, the arrival did
        # not fail and the chain verifies: then we sign it, and the DMARC
        # rule's From would add nothing.  Anything else falls back to it
        if not (list_fanout and self.list_instance()) or self.dkim2_off or not dkim2_keydir:
            return False
        if self.dkim2_arrival_status in DKIM2_NOT_VERIFIED:
            return False
        try:
            if not dkim2hop.find_key(keydir=dkim2_keydir, selector=dkim2_selector,
                                     domain=env_from_addr.rsplit("@", 1)[-1]):
                return False
            return self.dkim2_seen().result().status == "pass"
        except Exception:
            return False

    def dkim2_alias_path(self, env_from_addr):
        # ALIAS_DKIM2: will our signature carry this forward?  The message
        # came with a DKIM2 chain that verified, the copy will be signed
        # (split-then-sign, or the recipients are off-site already: a reply
        # to a wrap), we hold a key for the forwarding domain, and that
        # domain can extend the chain (-09 section 12.2).  Never a bounce:
        # its null sender stays null, and we do not sign for <>
        if not alias_dkim2 or self.dkim2_off or not dkim2_keydir or not env_from_addr:
            return False
        if self.dkim2_arrival_status != "pass":
            return False
        if not (dkim2_sign_daemon or self.offsite_rcpts()):
            return False
        try:
            if not dkim2hop.find_key(keydir=dkim2_keydir, selector=dkim2_selector,
                                     domain=forwarding_addr.rsplit("@", 1)[-1]):
                return False
            return dkim2hop.can_extend_chain(self.dkim2_seen(), forwarding_addr)
        except Exception:
            return False

    def dkim2_wants_new_from(self, hdr_from_addr, env_from_addr):
        # a list copy we are going to sign needs a From in our own domain
        # when nobody signed the post, or the list changed it since the last
        # DKIM2 signature (a footer, a subject tag, List-* fields): we answer
        # for the message then.  This is the decision mailman makes itself
        # (_dkim2_rewrites_from) unless it defers From to us, and it does not
        # depend on DMARC.  A From already ours is left alone
        if self.dkim2_off or not dkim2_keydir or self.dkim2_arrival_status in DKIM2_NOT_VERIFIED:
            return False
        try:
            return self.dkim2_changed_since_signature(hdr_from_addr, env_from_addr)
        except Exception:
            self.dkim2_give_up("the From rule")
            return False

    def dkim2_changed_since_signature(self, hdr_from_addr, env_from_addr):
        from_domain = hdr_from_addr.rsplit("@", 1)[-1].lower()
        if check_local(hdr_from_addr) or from_domain == forwarding_domain.lower():
            return False
        if not dkim2hop.find_key(keydir=dkim2_keydir, selector=dkim2_selector,
                                 domain=env_from_addr.rsplit("@", 1)[-1]):
            return False
        seen = self.dkim2_seen()
        # only take From over when we are going to sign for it.  Every
        # change since the last signature has to be recorded in an instance
        # (mailman's, with the Message-Instance patches); stock Mailman
        # records nothing, the chain it hands back does not verify, sign()
        # will refuse, and a rewritten From with no signature of ours
        # behind it helps nobody
        if seen.result().status != "pass":
            return False
        return seen.changed_since_signature()

    def dkim2_sign(self, queue_id, exploded):
        # last of all: sign for the envelope the message leaves in, or at
        # least say what we changed.  Only mail we relay off-site is
        # signed, and never over a chain that did not verify when it arrived
        if not dkim2_keydir:
            # nothing will sign over a change or a new recipient, so the
            # chain would not verify at the next hop: start it again instead.
            # Mail for a local list, unchanged, keeps it for mailman
            if self.offsite_rcpts() or self.header_changes:
                self.dkim2_strip(queue_id)
            return
        if dkim2_sign_daemon:
            # split then sign: the signing pass signs each copy for its
            # one recipient.  Say whether it is one of a list's many
            if exploded and not self.exploded_marks:
                self.addheader(DKIM2_EXPLODED, "yes")
            if exploded and not self.list_instance():
                # nothing recorded either: an instance of ours would have
                # the signing pass sign the copy after all
                logging.info(f"{queue_id} dkim2: not signing: the list gave no Message-Instance [{self.id}]")
            elif not self.dkim2_off:
                self.dkim2_record(queue_id, merge=exploded)
            return
        if self.dkim2_off:
            return
        if exploded and not self.list_instance():
            logging.info(f"{queue_id} dkim2: not signing: the list gave no Message-Instance [{self.id}]")
            return
        if dkim2_keydir and self.offsite_rcpts():
            if self.dkim2_arrival_status in DKIM2_NOT_VERIFIED:
                logging.info(f"{queue_id} dkim2: not signing, arrival was {self.dkim2_arrival_status} [{self.id}]")
            elif self.dkim2_signed(queue_id, exploded, merge=exploded):
                return
        self.dkim2_record(queue_id, merge=exploded)

    def list_instance(self):
        # list mail is only signed with DKIM2 when the list manager says what
        # it changed: mailman with dkim2_message_instance on hands every copy
        # back with a Message-Instance.  A copy with none (the setting off,
        # or stock Mailman) goes out as it is, DMARC rule and all
        return any(name.lower() == "message-instance" for name in self.dkim2_chain_fields)

    def dkim2_signed(self, queue_id, exploded, merge=False):
        # merge: a list's fan-out, whose changes go into mailman's instance
        mail_from = self.env_from_out or email.utils.parseaddr(self.mail_from)[1]
        try:
            signed = dkim2hop.sign(self.dkim2_seen(), self.fields_after_changes(),
                                   mail_from, self.mail_to, dkim2_keydir,
                                   exploded=exploded, selector=dkim2_selector, merge=merge)
        except Exception:
            self.dkim2_give_up("signing")
            return True
        if not signed:
            logging.info(f"{queue_id} dkim2: not signing: {signed.reason} [{self.id}]")
            return False
        for name, idx, value in signed.change:
            self.change_header(name, idx, value)
        # each goes in at the top, so the last one in is the first field
        for name, value in reversed(signed.insert):
            self.addheader(name, value, 0)
        if signed.change:
            logging.debug(f"{queue_id} dkim2: our header changes went into the list's Message-Instance [{self.id}]")
        logging.info(
            f"{queue_id} dkim2: signed d={signed.domain} for {mail_from} "
            f"({', '.join([n for n, _v in signed.insert] + [n for n, _i, _v in signed.change])}) [{self.id}]")
        return True

    def dkim2_sign_copy(self, queue_id):
        # the signing pass: one copy, one recipient, already rewritten and
        # recorded by the first pass.  Sign it as it is and change nothing
        # else; no lookups, and never a reason to hold the mail
        try:
            self.verp(queue_id)
            if not dkim2_keydir:
                self.dkim2_strip(queue_id)
            elif not self.dkim2_off and self.offsite_rcpts():
                # set only by the first pass (which replaces one from
                # outside) or by mailman, which we trust to relay it
                self.dkim2_arrival_status = self.dkim2_arrival_field()
                if self.dkim2_arrival_status in DKIM2_NOT_VERIFIED:
                    logging.info(f"{queue_id} dkim2 sign pass: not signing, arrival was "
                                 f"{self.dkim2_arrival_status} [{self.id}]")
                elif self.exploded_marks and not self.list_instance():
                    logging.info(f"{queue_id} dkim2 sign pass: not signing: the list gave no "
                                 f"Message-Instance [{self.id}]")
                else:
                    self.dkim2_signed(queue_id, exploded=self.exploded_marks > 0)
            for idx in range(self.exploded_marks, 0, -1):
                self.chgheader(DKIM2_EXPLODED, idx, None)
        except Exception:
            logging.exception(f"{queue_id} dkim2 sign pass: error, sending it on unsigned [{self.id}]")
        return Milter.ACCEPT

    def verp(self, queue_id):
        # one copy for one recipient: a list's -bounces sender becomes the
        # VERP address for that recipient, before it is signed for.  Any
        # failure leaves the sender as it was
        if not list_verp or len(self.mail_to) != 1:
            return
        env_from = email.utils.parseaddr(self.mail_from)[1]
        try:
            new_env_from = verp_sender(env_from, self.mail_to[0])
            if new_env_from:
                self.chgfrom(new_env_from)
                self.env_from_out = new_env_from
                logging.info(f"{queue_id} verp: Envelope-From changed from {env_from} to {new_env_from} [{self.id}]")
        except Exception:
            logging.exception(f"{queue_id} verp: error, Envelope-From left as {env_from} [{self.id}]")

    def dkim2_strip(self, queue_id):
        # no key to sign with: remove the whole chain, which leaves a
        # message with no DKIM2 at all rather than one that fails
        # (draft-ietf-dkim-dkim2-spec-09 13.1, 14.2).  Each field is
        # removed by its index among those of its name, last first
        removed = 0
        for name, count in self.dkim2_chain_fields.items():
            for idx in range(count, 0, -1):
                self.chgheader(name, idx, None)
                removed += 1
        if removed:
            logging.info(f"{queue_id} dkim2: no signing keys, removed {removed} DKIM2 header fields [{self.id}]")

    def dkim2_record(self, queue_id, merge=False):
        # we are not signing, but we may have changed header fields DKIM2
        # hashes (To and Cc unwrapped; From, for an alias).  Always say so,
        # in Message-Instance fields nobody has signed: the copy that goes
        # on to mailman keeps a chain that describes it, which the fan-out
        # signs over with mailman's instance and its own.  A copy that
        # leaves us like this will not verify at the next hop, but it
        # would not have with the change unrecorded, and now it says what
        # we did
        if not self.header_changes:
            return
        try:
            recorded = dkim2hop.record(self.dkim2_seen(), self.fields_after_changes(), merge=merge)
        except Exception:
            self.dkim2_give_up("recording changes")
            return
        if not recorded:
            logging.debug(f"{queue_id} dkim2: no instance added: {recorded.reason} [{self.id}]")
            return
        if recorded.change:
            # a list's fan-out: mailman's instance now says what we changed too
            for name, idx, value in recorded.change:
                self.change_header(name, idx, value)
            # (the same words as below: the log pipeline parses them)
            logging.debug(f"{queue_id} dkim2: our header changes went into the list's Message-Instance [{self.id}]")
            logging.info(f"{queue_id} dkim2: recorded our header changes in an unsigned Message-Instance [{self.id}]")
            return
        for name, value in reversed(recorded.insert):
            self.addheader(name, value, 0)
        logging.info(f"{queue_id} dkim2: recorded our header changes in an unsigned Message-Instance [{self.id}]")

    def eom(self):
        queue_id = None
        try:
            queue_id = self.getsymval('i') # queue id
            if self.dkim2_signing:
                return self.dkim2_sign_copy(queue_id)
            self.dkim2_arrival_status = self.dkim2_arrival(self.dkim2_verify_arrival(queue_id))
            result = self.rewrite(queue_id)
            if result in (Milter.ACCEPT, Milter.CONTINUE):
                auth_user = (self.getsymval('{auth_authen}') or '').lower()
                env_from_addr = email.utils.parseaddr(self.mail_from)[1]
                self.dkim2_sign(queue_id, exploded=(
                    auth_user == mailman_sasl_user
                    and bool(listbounce_mailmatch.search(env_from_addr))))
            return result
        except psycopg.OperationalError as e:
            logging.info(f"{queue_id} error: database unavailable: {e} [{self.id}]")
            self.setreply("451", "4.3.0", "backend unavailable")
            return Milter.TEMPFAIL
        except Exception:
            # TEMPFAIL drops any changes already made, so a half-rewritten
            # message is never accepted; the sender retries later
            logging.exception(f"{queue_id} error: unexpected failure [{self.id}]")
            self.setreply("451", "4.3.0", "rewriter internal error")
            return Milter.TEMPFAIL

    def rewrite(self, queue_id):
        # the address rewriting: returns the milter result.  Errors are
        # eom()'s to handle
        logging.debug(
            f"[{self.id}] Envelope-From: {self.mail_from}, Header-From: {self.header_from or 'N/A'}"
        )

        logging.debug(
            f"[{self.id}] Envelope-To: {self.mail_to or 'N/A'}, Header-To: {self.header_to or 'N/A'}"
        )

        _hdr_from_name, hdr_from_addr = email.utils.parseaddr(self.header_from)
        env_from_addr = email.utils.parseaddr(self.mail_from)[1]
        hdr_to_addr = email.utils.parseaddr(self.header_to)
        # mailman batches mix subscribers, so a wrapped recipient in the
        # batch must not skip the dmarc check below
        auth_user = (self.getsymval('{auth_authen}') or '').lower()
        list_fanout = auth_user == mailman_sasl_user and bool(listbounce_mailmatch.search(env_from_addr))

        # scenario 1
        if any(is_wrapped(item) for item in self.mail_to):
            logging.debug(
                f"debug: Header from: {hdr_from_addr} is remote, Header To: {hdr_to_addr} is wrapped local [{self.id}]"
            )
            added = self.unwrap_from_headers(queue_id)
            # we forward to the unwrapped addresses from our IPs, so the
            # replier's SPF fails and their DKIM rarely survives the
            # To:/Cc: rewrite.  Milter changes apply to every copy, so a
            # local list or ignored recipient alongside is rewritten too
            # (lmtp_generic_maps restores the From for mailman)
            if added and not list_fanout:
                # a wrapped list bounce may share the message
                self.unwrap_list_bounces(queue_id)
                self.rewrite_forwarded(_hdr_from_name, hdr_from_addr, env_from_addr, queue_id)
                return Milter.ACCEPT

        if list_fanout:
            # a mailman batch mixes subscribers, so decide from the sender:
            # one local list or alias in the batch must not decide for all
            self.unwrap_list_bounces(queue_id)
        elif any(listbounce_mailmatch.search(item) for item in self.mail_to):
            self.unwrap_list_bounces(queue_id)
            return Milter.ACCEPT

        # only ignored recipients: nothing to rewrite for.  Alongside
        # anyone else they are rewritten too, and Postfix's transport
        # for them restores the original From
        elif all(is_ignored(k) for k in self.rcpt_keys()):
            logging.info(
                f"{queue_id} none: Envelope To {self.mail_to} are all ignore list entries [{self.id}]"
            )
            return Milter.ACCEPT

        # scenario 2
        # an alias forwards off-site, so it needs the rewrite even when a
        # list shares the message; lmtp_generic_maps restores the From
        # on the copy delivered to mailman.  An ignored alias wants the
        # original From, so it doesn't count
        elif test_virtual_alias([k for k in self.rcpt_keys() if not is_ignored(k)]):
            logging.debug(
                f"{queue_id} debug: Virtual address recipient, check if rewrite needed Envelope-To: {self.mail_to} Header-To: {hdr_to_addr} [{self.id}]"
            )
            self.rewrite_forwarded(_hdr_from_name, hdr_from_addr, env_from_addr, queue_id)
            return Milter.ACCEPT
        # wraps and aliases are handled above, and Postfix only accepts
        # mailman's addresses or aliases in our domains, so the rest are
        # delivered to mailman here; a direct off-site recipient still
        # needs the rewrite below
        elif not self.offsite_rcpts():
            logging.info(
                f"{queue_id} none: no off-site recipients, no action needed Envelope-To: {self.mail_to} Header-To: {hdr_to_addr} [{self.id}]"
            )
            return Milter.ACCEPT
        # scenario 3
        if check_local(env_from_addr) and check_local(hdr_from_addr):
            logging.info(
                f"{queue_id} none: List source, no action needed Envelope-From: {env_from_addr} Header-From: {hdr_from_addr} [{self.id}]"
            )
            return Milter.ACCEPT
        # no scenario match
        else:
            logging.debug(f"{queue_id} debug: Fall through [{self.id}]")
            logging.debug(f"{queue_id} debug: env_from is {env_from_addr} [{self.id}]")
            logging.debug(f"{queue_id} debug: rewrite_domains are {rewrite_domain_map} [{self.id}]")
            logging.debug(f"{queue_id} debug: header from name is {_hdr_from_name} [{self.id}]")
            try:
                rewrite_domain = rewrite_domain_map[env_from_addr.rsplit("@", 1)[-1].lower()]
            except KeyError:
                rewrite_domain = forwarding_domain
            logging.info(f"rewrite domain is {rewrite_domain}")
            # a list copy DKIM2 will answer for is on the DKIM2 path: the
            # DMARC rule is not consulted, and the DKIM2 From rule decides
            on_path = list_fanout and self.dkim2_list_path(env_from_addr, list_fanout)
            if on_path:
                logging.debug(f"{queue_id} debug: on the DKIM2 path, From not rewritten for DMARC [{self.id}]")
            if (not on_path and check_dmarc(hdr_from_addr)) or (
                    list_fanout and self.dkim2_wants_new_from(hdr_from_addr, env_from_addr)):
                new_hdr_from_addr = wrap_addr(hdr_from_addr, forwarding_domain)
                self.change_header_from(_hdr_from_name, new_hdr_from_addr)
                # nobody replies to a bounce, so no wrap entry for it
                if env_from_addr:
                    update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
                new_env_from = self.change_env_from(env_from_addr, wrap_addr(env_from_addr, rewrite_domain), queue_id)
                if internal_addr(new_env_from) != internal_addr(new_hdr_from_addr):
                    self.log_envelope_wrap(env_from_addr, new_env_from)
                logging.info(
                    f"{queue_id} rewrite-both: Envelope-From changed from {env_from_addr or '<>'} to {new_env_from or '<>'} header-From changed from {hdr_from_addr} to {new_hdr_from_addr} [{self.id}]"
                )
            # SPF is checked on the MAIL FROM domain; we already send for
            # our local domains, so forwarding can't break theirs
            elif env_from_addr and not check_local(env_from_addr) and check_spf(env_from_addr):
                logging.info(
                    f"{queue_id} rewrite-envelope: SPF only, Header-From: {hdr_from_addr} Envelope-From: {env_from_addr or '<>'} [{self.id}]"
                )
                try:
                    new_env_from = self.change_env_from(env_from_addr, wrap_addr(env_from_addr, rewrite_domain), queue_id)
                except Exception as e:
                    logging.info(f"{queue_id} error: chgfrom failed: {e} [{self.id}]")
                else:
                    self.log_envelope_wrap(env_from_addr, new_env_from)
                return Milter.ACCEPT
            else:
                logging.info(
                    f"{queue_id} none: No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr} [{self.id}]"
                )
            return Milter.ACCEPT

        return Milter.CONTINUE


def main():
    timeout = 600

    # without DKIM2 nothing here reads the body: ask the MTA not to send it
    nocallback = getattr(Milter, "nocallback", None)
    if nocallback and not (dkim2_keydir or dkim2_authserv_id):
        EnvelopeMilter.eoh = nocallback(EnvelopeMilter.eoh)
        EnvelopeMilter.body = nocallback(EnvelopeMilter.body)

    Milter.factory = EnvelopeMilter
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGFROM | Milter.CHGHDRS | Milter.ADDRCPT | Milter.DELRCPT)

    def run_milter():
        Milter.runmilter("EnvelopeMilter", "inet:" + milter_listening_port, timeout)

    def run_http():
        server_address = ("", int(http_listening_port))
        # Create an instance of the threaded HTTP server
        httpd = ThreadingHTTPServer(server_address, SimpleHTTPRequestHandler)
        httpd.serve_forever()

    threads = []
    threads.append(threading.Thread(target=run_milter))
    threads.append(threading.Thread(target=run_http))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    logging.info(
        f"info: Starting, milter interface listening on {milter_listening_port}"
    )
    logging.info(f"info: http interface listening on {http_listening_port}")
    logging.info(f"info: Local domains are: {local_domains}")
    logging.info(f"info: logging rotation period is {logging_rotate_period}")

    main()

