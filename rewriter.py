#!/usr/bin/env python3
import email.errors
import email.utils
from email.header import Header, decode_header, make_header

from expiringdict import ExpiringDict
import logging
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import TimedRotatingFileHandler

import checkdmarc
import Milter
import psycopg
from psycopg_pool import ConnectionPool

forwarding_addr = os.environ.get("FORWARDING_ADDR", "forwardingalgorithm@myaddr.com")
forwarding_domain = os.environ.get("FORWARDING_DOMAIN", "myaddr.com")
local_domains = os.environ.get("LOCAL_DOMAINS", forwarding_domain)
rewrite_domains = os.environ.get("REWRITE_DOMAINS", "map[mydomain.com:dmarc.mydomain.com]")

def parse_ignore_list(value):
    # comma separated; entries are trimmed and matched case-insensitively
    return {x.strip().lower() for x in value.split(',') if x.strip()}

ignore_list = parse_ignore_list(os.environ.get("IGNORELIST", "alldanes@lists.sys.slush.ca"))
mailman_sasl_user = os.environ.get("MAILMAN_SASL_USER", "mailman@ietf.org").lower()

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
def get_db_pool() -> ConnectionPool:
    global _db_pool
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


def test_local_list(email_addr):
    with get_db_pool().connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT list from mailman_lists where list = ANY(%s)", [email_addr])
        result = cur.fetchall()
        return len(result) > 0

def test_virtual_alias(email_addr):
    should_ignore = ignore_list & set(email_addr)
    if not should_ignore:
        with get_db_pool().connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT email from virtual where email = ANY(%s)", [email_addr])
            result = cur.fetchall()
        return len(result) > 0
    else:
        return False

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
    if "timed out" in dmarc_status.get("error", "").lower():
        return None
    return False

def _check_spf_uncached(domain):
    matches = ["softfail", "fail"]
    spf_status = checkdmarc.check_spf(domain, timeout=1.0, timeout_retries=2)
    logging.debug(f"spf status is {spf_status}")
    if "parsed" in spf_status:
        return any(x in spf_status["parsed"]["all"] for x in matches)
    if "timed out" in spf_status.get("error", "").lower():
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

def is_wrapped(addr):
    # list bounces are wrapped too, but unwrap_list_bounces() handles those
    key = internal_addr(addr)
    return bool(wrapped_mailmatch.search(key)) and not listbounce_mailmatch.search(key)

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

    def envfrom(self, f, *str):
        # one milter instance serves every message on an SMTP connection
        self.mail_to = []
        self.header_from = None
        self.header_to = None
        # addresses keep their case: local parts (SRS, VERP) can be case
        # sensitive and delrcpt() must name the recipient exactly as given;
        # internal_addr() gives the lowercased form for comparisons
        self.mail_from = f
        return Milter.CONTINUE

    def envrcpt(self, to, *str):
        self.mail_to.append(email.utils.parseaddr(to)[1])
        return Milter.CONTINUE

    def rcpt_keys(self):
        # recipients as the lowercased, unquoted keys used in the database
        return [internal_addr(addr) for addr in self.mail_to]

    def header(self, name, value):
        if name.lower() == "from":
            self.header_from = value
        if name.lower() == "to":
            self.header_to = value
        return Milter.CONTINUE

    def change_env_from(self, env_from_addr, new_addr, queue_id):
        # RFC 5321 4.5.5: a null sender (bounce, DSN) must stay null so a
        # failed delivery can't bounce back to us and loop
        if not env_from_addr:
            logging.info(f"{queue_id} none: null Envelope-From kept, not changed to {new_addr} [{self.id}]")
            return env_from_addr
        self.chgfrom(new_addr)
        return new_addr

    def unwrap_list_bounces(self, queue_id):
        # a -bounces recipient in a rewrite domain was wrapped by us on the
        # way out (list-bounces=40list.domain@dmarc.domain); restore it
        for i, addr in enumerate(self.mail_to):
            if not listbounce_mailmatch.search(addr):
                continue
            local, domain = internal_addr(addr).rsplit('@', 1)
            if domain not in rewrite_domain_reverse_map or '=40' not in local:
                logging.info(f"{queue_id} none: list bounce already unwrapped {addr} [{self.id}]")
                continue
            unwrapped_addr = unwrap_addr(addr)
            logging.info(f"{queue_id} unwrap: list bounce unwrapped from {addr} to {unwrapped_addr} [{self.id}]")
            self.delrcpt(addr)
            self.addrcpt(f"<{unwrapped_addr}>")
            self.mail_to[i] = unwrapped_addr

    def eom(self):
        queue_id = None
        try:
            queue_id = self.getsymval('i') # queue id
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
                only_wrapped = all(is_wrapped(item) for item in self.mail_to)
                for i, addr in enumerate(self.mail_to):
                    if is_wrapped(addr):
                        unwrapped_addr = unwrap_addr(addr)
                        try:
                            with get_db_pool().connection() as conn, conn.cursor() as cur:
                                cur.execute("""
                                            SELECT email FROM
                                            virtual WHERE email = %s and
                                            updated >= NOW() - INTERVAL '30 DAYS';
                                            """, (internal_addr(addr),))
                                valid_unwraps = cur.fetchall()
                        except psycopg.OperationalError as e:
                            logging.info(f"failed to find valid rewrite: {e}")
                            valid_unwraps = []
                        except psycopg.ProgrammingError as e:
                            logging.info(f"failed to find valid rewrite: {e}")
                            valid_unwraps = []
                        logging.debug(
                            f"debug: Header from: {hdr_from_addr} is remote, Header To: {hdr_to_addr} is wrapped local [{self.id}]"
                        )
                        logging.info(
                            f"{queue_id} unwrap: from {addr} to {unwrapped_addr} [{self.id}]"
                        )
                        if len(valid_unwraps) > 0:
                            self.delrcpt(addr)
                            self.addrcpt(f"<{unwrapped_addr}>")
                            self.mail_to[i] = unwrapped_addr

                        else:
                            logging.info(f"{queue_id} unwrap: failed to find valid unwrapping addr for {addr}, unwrapping regardless")
                            self.delrcpt(addr)
                            self.addrcpt(f"<{unwrapped_addr}>")
                            self.mail_to[i] = unwrapped_addr
                # other recipients (e.g. a virtual alias on CC) still need
                # the checks below
                if only_wrapped and not list_fanout:
                    return Milter.ACCEPT

            if list_fanout:
                # a mailman batch mixes subscribers, so decide from the sender:
                # one local list or alias in the batch must not decide for all
                self.unwrap_list_bounces(queue_id)
            elif any(listbounce_mailmatch.search(item) for item in self.mail_to):
                self.unwrap_list_bounces(queue_id)
                return Milter.ACCEPT

            # scenario 2
            elif test_local_list(self.rcpt_keys()):
                logging.info(
                    f"{queue_id} none: Local list recipient, no action needed Envelope-To: {self.mail_to} Header-To: {hdr_to_addr} [{self.id}]"
                )
                return Milter.ACCEPT
            elif test_virtual_alias(self.rcpt_keys()):
                logging.debug(
                    f"{queue_id} debug: Virtual address recipient, check if rewrite needed Envelope-To: {self.mail_to} Header-To: {hdr_to_addr} [{self.id}]"
                )
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = wrap_addr(hdr_from_addr, forwarding_domain)
                    # nobody replies to a bounce, so no wrap entry for it
                    if env_from_addr:
                        update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
                    new_env_from = self.change_env_from(env_from_addr, forwarding_addr, queue_id)
                    self.chgheader(
                        "From",
                        0,
                        format_from_header(_hdr_from_name, new_hdr_from_addr),
                    )
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
                # an ignored subscriber must not exempt a whole mailman batch
                if not list_fanout and ignore_list & set(self.rcpt_keys()):
                    logging.info(
                        f"{queue_id} none: Envelope To {self.mail_to} contains an ignore list entry"
                    )
                    return Milter.ACCEPT
                if check_dmarc(hdr_from_addr):
                    new_hdr_from_addr = wrap_addr(hdr_from_addr, forwarding_domain)
                    self.chgheader(
                        "From",
                        0,
                        format_from_header(_hdr_from_name, new_hdr_from_addr),
                    )
                    # nobody replies to a bounce, so no wrap entry for it
                    if env_from_addr:
                        update_addr_wrap_log(hdr_from_addr, new_hdr_from_addr)
                    new_env_from = self.change_env_from(env_from_addr, wrap_addr(env_from_addr, rewrite_domain), queue_id)
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
                        self.change_env_from(env_from_addr, wrap_addr(env_from_addr, rewrite_domain), queue_id)
                    except Exception as e:
                        logging.info(f"{queue_id} error: chgfrom failed: {e} [{self.id}]")
                    return Milter.ACCEPT
                else:
                    logging.info(
                        f"{queue_id} none: No change for Envelope-From {env_from_addr} or Header-From {hdr_from_addr} [{self.id}]"
                    )
                return Milter.ACCEPT

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
        return Milter.CONTINUE


def main():
    timeout = 600

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

