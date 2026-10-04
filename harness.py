#!/usr/bin/env python3
"""Offline test harness for rewriter.py.

Drives EnvelopeMilter through envfrom/envrcpt/header/eom with a fake milter
context and an in-memory stand-in for the postfix database, then prints what
the milter decided: the result code, envelope-from and From-header rewrites,
recipient changes and database writes.

  # one sender, one destination
  ./harness.py --from 'Alice <alice@yahoo.com>' --to bob@example.com

  # several destinations in one message
  ./harness.py --from alice@yahoo.com --to a@example.com b@example.net

  # a mailman fan-out of --list (only when --list is given)
  ./harness.py --from alice@yahoo.com --list ietf@ietf.org --to a@example.com b@example.net c@example.org

  # set the envelope sender (MAIL FROM) separately from the From header
  ./harness.py --from alice@yahoo.com --env-from bounces@mailer.yahoo.com --to bob@example.com

  # a recipient on the ignore list (overrides IGNORELIST; repeatable)
  ./harness.py --from alice@yahoo.com --to alldanes@lists.sys.slush.ca --ignore alldanes@lists.sys.slush.ca

  # a quoted local part: wrapped as "john smith=40example.com"@<FORWARDING_DOMAIN>
  ./harness.py --from '"john smith"@example.com' --to bob@example.net --dmarc example.com=reject

  # ...and the reply to it being unwrapped (--virtual takes the unquoted form)
  ./harness.py --from bob@example.net --to '"john smith=40example.com"@dmarc.ietf.org' \
      --virtual 'john smith=40example.com@dmarc.ietf.org'

  # a bounce (null sender): the From header may be rewritten, the envelope stays <>
  ./harness.py -f '' --from MAILER-DAEMON@example.com --to bob@example.net --dmarc example.com=reject

  # a subdomain sender: the parent's record applies, with its sp= policy
  ./harness.py --from alice@lists.example.com --to bob@example.net --dmarc 'example.com=p=none;sp=reject'

  # a bounce coming back to a wrapped list address
  ./harness.py --from MAILER-DAEMON@example.com --to ietf-bounces=40ietf.org@dmarc.ietf.org

No database is contacted.  DMARC and SPF are checked by the real checkdmarc;
--dmarc/--spf pin a domain's DNS records, and other lookups go to live DNS
unless --no-dns is given.  Configuration comes from the
usual rewriter environment variables; the defaults below are only used when
those are unset.
"""
import argparse
import email.utils
import json
import os
import sys
import tempfile
import traceback
import types
from contextlib import contextmanager

HERE = os.path.dirname(os.path.abspath(__file__))

DEFAULT_ENV = {
    "FORWARDING_DOMAIN": "dmarc.ietf.org",
    "FORWARDING_ADDR": "forwardingalgorithm@dmarc.ietf.org",
    "LOCAL_DOMAINS": "ietf.org",
    "REWRITE_DOMAINS": "map[ietf.org:dmarc.ietf.org]",
    "MAILMAN_SASL_USER": "mailman@ietf.org",
    "IGNORELIST": "",
}

QUEUE_ID = "HARNESS01"


# --- stubs for modules that may not be installed locally --------------------

def _stub_milter():
    m = types.ModuleType("Milter")
    m.CONTINUE, m.REJECT, m.DISCARD, m.ACCEPT, m.TEMPFAIL = 0, 1, 2, 3, 4
    m.ADDHDRS, m.CHGBODY, m.ADDRCPT, m.DELRCPT = 0x01, 0x02, 0x04, 0x08
    m.CHGHDRS, m.QUARANTINE, m.CHGFROM, m.ADDRCPT_PAR = 0x10, 0x20, 0x40, 0x80
    m.SETSYMLIST = 0x100
    m.MODBODY = m.CHGBODY
    m.CURR_ACTS = 0x1FF
    counter = iter(range(1, 1 << 30))
    m.uniqueID = lambda: next(counter)
    m.set_flags = lambda flags: None

    def runmilter(*a, **kw):
        raise RuntimeError("stub Milter cannot run a real milter")
    m.runmilter = runmilter

    class Base:
        def _setctx(self, ctx):
            self._ctx = ctx

        def getsymval(self, sym):
            return self._ctx.getsymval(sym)

        def setreply(self, rcode, xcode=None, msg=None, *ml):
            return self._ctx.setreply(rcode, xcode, msg, *ml)

        def addheader(self, field, value, idx=-1):
            return self._ctx.addheader(field, value, idx)

        def chgheader(self, field, idx, value):
            return self._ctx.chgheader(field, idx, value)

        def addrcpt(self, rcpt, params=None):
            return self._ctx.addrcpt(rcpt, params)

        def delrcpt(self, rcpt):
            return self._ctx.delrcpt(rcpt)

        def chgfrom(self, sender, params=None):
            return self._ctx.chgfrom(sender, params)
    m.Base = Base
    return m


def _stub_psycopg():
    pg = types.ModuleType("psycopg")

    class Error(Exception):
        pass

    class OperationalError(Error):
        pass

    class ProgrammingError(Error):
        pass
    pg.Error, pg.OperationalError, pg.ProgrammingError = Error, OperationalError, ProgrammingError

    pool = types.ModuleType("psycopg_pool")

    class PoolTimeout(OperationalError):
        pass

    class ConnectionPool:
        check_connection = staticmethod(lambda conn: None)

        def __init__(self, *a, **kw):
            raise RuntimeError("stub ConnectionPool: the harness replaces get_db_pool()")
    pool.PoolTimeout, pool.ConnectionPool = PoolTimeout, ConnectionPool
    return pg, pool


def _stub_expiringdict():
    mod = types.ModuleType("expiringdict")

    class ExpiringDict(dict):
        # no expiry: the harness handles a single message per process
        def __init__(self, max_len=None, max_age_seconds=None, items=None):
            super().__init__()
    mod.ExpiringDict = ExpiringDict
    return mod


def install_stubs():
    stubbed = []
    for name, factory in (("Milter", _stub_milter),
                          ("expiringdict", _stub_expiringdict)):
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = factory()
            stubbed.append(name)
    try:
        import psycopg  # noqa: F401
        import psycopg_pool  # noqa: F401
    except ImportError:
        pg, pool = _stub_psycopg()
        sys.modules["psycopg"], sys.modules["psycopg_pool"] = pg, pool
        stubbed += ["psycopg", "psycopg_pool"]
    return stubbed


# --- fake database -----------------------------------------------------------

class FakeDB:
    """Answers the queries rewriter.py issues against the postfix database."""

    def __init__(self, virtual, down):
        self.virtual = set(virtual)
        self.down = down
        self.writes = []
        self.queries = []

    @contextmanager
    def connection(self, timeout=None):
        if self.down:
            import psycopg_pool
            raise psycopg_pool.PoolTimeout("harness: database marked down (--db-down)")
        yield FakeConn(self)


class FakeConn:
    def __init__(self, db):
        self.db = db

    @contextmanager
    def cursor(self):
        yield FakeCursor(self.db)


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self.rows = []

    def execute(self, sql, params=()):
        q = " ".join(sql.split()).lower()
        self.db.queries.append((q, params))
        if "from virtual" in q and "any(" in q:
            self.rows = [(a,) for a in params[0] if a in self.db.virtual]
        elif "from virtual" in q and "email = %s" in q:
            self.rows = [(params[0],)] if params[0] in self.db.virtual else []
        elif "from virtual" in q and "limit 1" in q:
            self.rows = [("healthz",)]
        elif q.startswith("insert into virtual"):
            email_addr, destination = params
            self.db.virtual.add(email_addr)
            self.db.writes.append({"table": "virtual", "email": email_addr,
                                   "destination": destination})
            self.rows = []
        else:
            import psycopg
            raise psycopg.ProgrammingError(f"harness: unhandled query: {q}")

    def fetchall(self):
        return self.rows


# --- fake DNS ------------------------------------------------------------------
#
# rewriter calls the real checkdmarc, which builds a dns.resolver.Resolver for
# each lookup.  FakeDNS stands in for that resolver, answering from the pinned
# --dmarc/--spf answers, so checkdmarc's record parsing, DMARCbis tree walk,
# retries and error messages are the real ones.

DNS_FAILURES = ("timeout", "timeout-empty", "servfail", "nxdomain")
NAMESERVER = "192.0.2.1"

SPF_QUALIFIERS = {"fail": "-all", "softfail": "~all", "neutral": "?all", "pass": "+all"}


def dmarc_record(answer):
    """A pinned DMARC answer ('reject', 'p=none;sp=reject' or a whole record) as TXT."""
    if answer.lower().startswith("v=dmarc1"):
        return answer
    tags = [t.strip() for t in answer.split(";") if t.strip()]
    return "; ".join(["v=DMARC1", *(t if "=" in t else f"p={t}" for t in tags)])


def spf_record(answer):
    """A pinned SPF answer ('-all', 'softfail' or a whole record) as TXT."""
    if answer.lower().startswith("v=spf1"):
        return answer
    return f"v=spf1 {SPF_QUALIFIERS.get(answer.lower(), answer)}"


def is_under(name, domain):
    return name == domain or name.endswith("." + domain)


class FakeDNS:
    """The resolver checkdmarc uses, with pinned zones and no network.

    A --dmarc pin publishes a record at _dmarc.<domain>; a --spf pin publishes
    a TXT record at <domain>.  Other names at or under a pinned domain exist
    but have no records, so checkdmarc's tree walk reaches a parent's pin.  A
    failure pin (timeout, servfail, nxdomain) applies to every such name.
    Anything else goes to live DNS, or doesn't exist with --no-dns.
    """

    # checkdmarc sets these on the resolver it builds
    nameservers = timeout = lifetime = None

    def __init__(self, dmarc, spf, no_dns):
        self.dmarc, self.spf, self.no_dns = dmarc, spf, no_dns
        self.queries = []
        self._real_resolver = None
        self._live = None

    @contextmanager
    def installed(self):
        import dns.resolver
        real = dns.resolver.Resolver
        self._real_resolver = real
        dns.resolver.Resolver = lambda *a, **kw: self
        try:
            yield
        finally:
            dns.resolver.Resolver = real

    def _answer(self, name, rdtype):
        """A list of TXT strings (empty: no answer), a failure name, or None for live DNS."""
        if name.startswith("_dmarc."):
            target = name[len("_dmarc."):]
            for domain, answer in self.dmarc.items():
                if is_under(target, domain):
                    if answer.lower() in DNS_FAILURES:
                        return answer.lower()
                    if target == domain:
                        return [dmarc_record(answer)] if rdtype == "TXT" else []
        answer = self.spf.get(name)
        if answer is not None:
            if answer.lower() in DNS_FAILURES:
                return answer.lower()
            return [spf_record(answer)] if rdtype == "TXT" else []
        pins = [a.lower() for d, a in (*self.dmarc.items(), *self.spf.items()) if is_under(name, d)]
        if pins:
            return "nxdomain" if "nxdomain" in pins else []
        return "nxdomain" if self.no_dns else None

    def resolve(self, qname, rdtype="A", *args, lifetime=None, **kw):
        import dns.exception
        import dns.message
        import dns.name
        import dns.rdataclass
        import dns.rdatatype
        import dns.resolver
        from dns.rdtypes.ANY.TXT import TXT

        name = str(qname).rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        answer = self._answer(name, rdtype)
        if answer is None:
            self.queries.append((name, rdtype, "live DNS"))
            if self._live is None:
                self._live = self._real_resolver()
            return self._live.resolve(qname, rdtype, *args, lifetime=lifetime, **kw)
        self.queries.append((name, rdtype, answer if isinstance(answer, str) else (answer or "no answer")))

        qname = dns.name.from_text(name)
        lifetime = lifetime or self.lifetime or 1.0
        if answer == "nxdomain":
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses={})
        if answer == "timeout":
            raise dns.resolver.LifetimeTimeout(
                timeout=lifetime, errors=[(NAMESERVER, False, 53, dns.exception.Timeout(), None)])
        if answer == "timeout-empty":
            raise dns.resolver.LifetimeTimeout(timeout=lifetime, errors=[])
        if answer == "servfail":
            raise dns.resolver.NoNameservers(request=dns.message.make_query(qname, rdtype),
                                             errors=[(NAMESERVER, False, 53, "SERVFAIL", None)])
        if not answer:
            raise dns.resolver.NoAnswer()
        # a TXT string is at most 255 bytes; longer records come in chunks
        return [TXT(dns.rdataclass.IN, dns.rdatatype.TXT,
                    [b[i:i + 255] for i in range(0, len(b), 255)])
                for b in (r.encode() for r in answer)]


class LoggedCheckdmarc:
    """The real checkdmarc, answering from a FakeDNS and logging each check."""

    def __init__(self, fake_dns):
        import checkdmarc
        import checkdmarc.utils
        self.real, self.dns = checkdmarc, fake_dns
        self.lookups = []
        # checkdmarc keeps its own answers; start each run from a cold cache
        checkdmarc.utils.DNS_CACHE.clear()

    def _check(self, kind, fn, summarize, domain, kw):
        before = len(self.dns.queries)
        with self.dns.installed():
            result = fn(domain, **kw)
        summary = summarize(result, domain) if "error" not in result else result["error"]
        if any(q[2] == "live DNS" for q in self.dns.queries[before:]):
            summary += "  (live DNS)"
        self.lookups.append((kind, domain, summary))
        return result

    def check_dmarc(self, domain, **kw):
        def summarize(r, domain):
            location = (r.get("location") or domain).rstrip(".").lower()
            return r["record"] + ("" if location == domain else f"  (at {location})")
        return self._check("dmarc", self.real.check_dmarc, summarize, domain, kw)

    def check_spf(self, domain, **kw):
        return self._check("spf", self.real.check_spf, lambda r, _d: r["record"], domain, kw)


# --- fake milter context -----------------------------------------------------

class FakeCtx:
    def __init__(self, macros):
        self.macros = macros
        self.actions = []
        self.reply = None
        self.priv = None

    def setpriv(self, priv):
        self.priv = priv

    def getpriv(self):
        return self.priv

    def getsymval(self, sym):
        return self.macros.get(sym)

    def setreply(self, rcode, xcode, msg, *ml):
        self.reply = " ".join(x for x in (rcode, xcode, msg, *ml) if x)

    def chgfrom(self, sender, params=None):
        self.actions.append(("chgfrom", sender))

    def chgheader(self, field, idx, value):
        self.actions.append(("chgheader", field, idx, value))

    def addheader(self, field, value, idx=-1):
        self.actions.append(("addheader", field, value))

    def addrcpt(self, rcpt, params=None):
        self.actions.append(("addrcpt", rcpt))

    def delrcpt(self, rcpt):
        self.actions.append(("delrcpt", rcpt))


# --- SMTP transcript ---------------------------------------------------------

class Transcript:
    def __init__(self):
        self.lines = []

    def title(self, text):
        self.lines += ["", f"--- {text} ---"]

    def c(self, *lines):
        self.lines += [f"C: {x}" for x in lines]

    def s(self, *lines):
        self.lines += [f"S: {x}" for x in lines]

    def milter(self, text):
        self.lines.append(f"   [milter] {text}")

    def note(self, text):
        self.lines.append(f"   ({text})")


def smtp_reply(result, reply, ok):
    """The reply Postfix gives the client for a milter result at some stage."""
    if result in ("CONTINUE", "ACCEPT", "DISCARD"):
        return ok
    if reply:
        return reply
    return {"TEMPFAIL": "451 4.7.1 Service unavailable - try again later",
            "REJECT": "550 5.7.1 Command rejected"}.get(result, ok)


def apply_header_changes(headers, actions):
    headers = list(headers)
    for a in actions:
        if a[0] == "chgheader":
            field, idx, value = a[1], max(a[2], 1), a[3]
            seen = 0
            for i, (k, _v) in enumerate(headers):
                if k.lower() == field.lower():
                    seen += 1
                    if seen == idx:
                        headers[i] = (k, value)
                        break
            else:
                headers.append((field, value))
        elif a[0] == "addheader":
            headers.append((a[1], a[2]))
    return headers


def relay_sessions(tx, server, client, auth, env_from, rcpts, headers, body, local_domains):
    """Postfix's onward delivery after cleanup applied the milter's changes."""
    sender = email.utils.parseaddr(env_from)[1] or env_from
    received = (f"from {client} ({client} [192.0.2.10]) by {server} (Postfix) "
                f"with ESMTP{'SA' if auth else ''} id {QUEUE_ID}; "
                f"{email.utils.formatdate(localtime=True)}")
    by_domain = {}
    for r in rcpts:
        by_domain.setdefault(r.rsplit("@", 1)[-1], []).append(r)
    for domain, rs in by_domain.items():
        if domain in local_domains:
            tx.title(f"{server}: local delivery  ({domain} is in LOCAL_DOMAINS)")
            tx.note(f"envelope <{sender}> -> {', '.join(rs)}; "
                    f"handed to Mailman / virtual alias expansion, not relayed")
            continue
        mx = f"mx.{domain}"
        tx.title(f"{server} -> {mx}  (outbound relay, after milter changes)")
        tx.s(f"220 {mx} ESMTP")
        tx.c(f"EHLO {server}")
        tx.s(f"250-{mx}", "250-STARTTLS", "250-8BITMIME", "250 SMTPUTF8")
        tx.note("STARTTLS negotiation omitted")
        tx.c(f"MAIL FROM:<{sender}>")
        tx.s("250 2.1.0 Ok")
        for r in rs:
            tx.c(f"RCPT TO:<{r}>")
            tx.s("250 2.1.5 Ok")
        tx.c("DATA")
        tx.s("354 End data with <CR><LF>.<CR><LF>")
        tx.c(f"Received: {received}")
        for k, v in headers:
            tx.c(f"{k}: {v}")
        tx.c("", *body, ".")
        tx.s("250 2.0.0 Ok: queued")
        tx.c("QUIT")
        tx.s("221 2.0.0 Bye")


# --- driver ------------------------------------------------------------------

def parse_pins(values, flag):
    pins = {}
    for v in values or []:
        domain, sep, answer = v.partition("=")
        if not sep:
            sys.exit(f"{flag} expects DOMAIN=ANSWER, got {v!r}")
        pins[domain.lower()] = answer
    return pins


def build_parser():
    p = argparse.ArgumentParser(
        description="Run one message through rewriter.py's milter logic offline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"DNS answers for --dmarc/--spf: a policy (reject, quarantine, none, or tags such as "
               f"'p=none;sp=reject' / -all, ~all, ?all, +all or fail, softfail, neutral, pass), "
               f"a whole record ('v=DMARC1; p=reject; rua=mailto:...' / 'v=spf1 ...'), "
               f"or a failure ({', '.join(DNS_FAILURES)}). The answers are served as DNS "
               f"records to the real checkdmarc, whose tree walk also finds a --dmarc record "
               f"for the domain's subdomains.")
    p.add_argument("--from", dest="source", default="sender@example.com",
                   help="From header, e.g. 'Alice <alice@yahoo.com>' (default: %(default)s)")
    p.add_argument("--to", nargs="+", default=None,
                   help="destination address(es); required unless --list is given "
                        "(then defaults to the --list address)")
    p.add_argument("--cc", nargs="+", default=[], metavar="ADDR",
                   help="address(es) for a Cc header, also added as envelope recipients")
    p.add_argument("--bcc", nargs="+", default=[], metavar="ADDR",
                   help="envelope-only recipient(s), named in no header")
    p.add_argument("--header", action="append", default=[], metavar="'NAME: VALUE'",
                   help="extra header line, e.g. 'Cc: Alice <alice@example.com>' (repeatable)")
    p.add_argument("--list", default=None, metavar="ADDR",
                   help="treat the message as a mailman fan-out from this list")
    p.add_argument("-f", "--env-from", "--mail-from", dest="env_from", metavar="ADDR",
                   help="envelope sender (MAIL FROM); default: the --from address, or "
                        "<list>-bounces@<domain> for a fan-out. Use '' for the null sender <>")
    p.add_argument("--auth", help="override the SASL user ({auth_authen})")
    p.add_argument("--virtual", action="append", default=[], metavar="ADDR",
                   help="address present in the virtual table (aliases and valid wraps)")
    p.add_argument("--ignore", action="append", metavar="ADDR",
                   help="address on the ignore list; replaces IGNORELIST from the environment "
                        "(repeatable; --ignore '' for an empty list)")
    p.add_argument("--db-down", action="store_true", help="every database call times out")
    p.add_argument("--dmarc", action="append", metavar="DOMAIN=POLICY", help="pin a DMARC answer")
    p.add_argument("--spf", action="append", metavar="DOMAIN=ALL", help="pin an SPF answer")
    p.add_argument("--no-dns", action="store_true",
                   help="no live DNS: unpinned domains answer as nonexistent")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    p.add_argument("--debug", action="store_true",
                   help="show the SMTP sessions: inbound with milter calls, then the relay after rewriting")
    p.add_argument("-v", "--verbose", action="store_true", help="show rewriter debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="hide rewriter logging")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    for k, v in DEFAULT_ENV.items():
        os.environ.setdefault(k, v)
    os.environ["LOG_LEVEL"] = "DEBUG" if args.verbose else ("WARNING" if args.quiet else "INFO")
    log_dir = tempfile.mkdtemp(prefix="rewriter-harness-")
    os.environ["LOGGING_FILENAME"] = os.path.join(log_dir, "rewrite.log")

    stubbed = install_stubs()
    sys.path.insert(0, HERE)
    import rewriter
    import Milter

    fake_dns = FakeDNS(parse_pins(args.dmarc, "--dmarc"), parse_pins(args.spf, "--spf"), args.no_dns)
    checks = rewriter.checkdmarc = LoggedCheckdmarc(fake_dns)

    fanout = args.list is not None
    list_addr = args.list.lower() if fanout else None
    if fanout:
        list_local, list_domain = list_addr.rsplit("@", 1)
    elif not args.to:
        build_parser().error("--to is required unless --list is given")
    db = FakeDB(virtual=(a.lower() for a in args.virtual),
                down=args.db_down)
    rewriter.get_db_pool = lambda: db
    # applied on every run, not only at import, so one process can run many
    ignore_value = ",".join(args.ignore) if args.ignore is not None else os.environ.get("IGNORELIST", "")
    rewriter.ignore_list = ignore_list = rewriter.parse_ignore_list(ignore_value)

    header_from = args.source
    source_addr = email.utils.parseaddr(header_from)[1]
    recipients = args.to or [list_addr]

    if fanout:
        default_env_from = f"{list_local}-bounces@{list_domain}"
        auth = args.auth if args.auth is not None else rewriter.mailman_sasl_user
        header_to = list_addr
    else:
        default_env_from = source_addr
        auth = args.auth or ""
        header_to = ", ".join(recipients)
    recipients = recipients + args.cc + args.bcc
    env_from = args.env_from.strip("<>") if args.env_from is not None else default_env_from

    ctx = FakeCtx({"i": QUEUE_ID, "{auth_authen}": auth or None})
    m = rewriter.EnvelopeMilter()
    if hasattr(m, "_setctx"):
        m._setctx(ctx)
    m._ctx = ctx
    m._actions = Milter.CURR_ACTS

    codes = {getattr(Milter, n): n for n in ("CONTINUE", "REJECT", "DISCARD", "ACCEPT", "TEMPFAIL")}

    def code_name(rc):
        return codes.get(rc, repr(rc))

    local_domains = os.environ.get("LOCAL_DOMAINS", "").lower().split()
    server = f"mx.{local_domains[0]}" if local_domains else "mx.harness.test"
    sender_domain = source_addr.rsplit("@", 1)[-1] if "@" in source_addr else "example.com"
    client = f"mailman.{list_domain}" if fanout else f"mail.{sender_domain}"
    headers = [("From", header_from), ("To", header_to),
               ("Subject", "rewriter harness test"),
               ("Date", email.utils.formatdate(localtime=True)),
               ("Message-ID", email.utils.make_msgid(domain=client))]
    if args.cc:
        headers.insert(2, ("Cc", ", ".join(args.cc)))
    if fanout:
        headers.append(("List-Id", f"<{list_local}.{list_domain}>"))
    for line in args.header:
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            build_parser().error(f"--header {line!r} is not 'NAME: VALUE'")
        headers.append((name.strip(), value.strip()))
    body = ["This message was generated by harness.py."]

    # drive the milter in SMTP order, recording the session as we go
    tx = Transcript()
    tx.title(f"{client} -> {server}  (inbound, milter attached)")
    tx.s(f"220 {server} ESMTP Postfix")
    tx.c(f"EHLO {client}")
    tx.s(f"250-{server}", "250-PIPELINING", "250-AUTH PLAIN LOGIN",
         "250-ENHANCEDSTATUSCODES", "250-8BITMIME", "250 SMTPUTF8")
    if auth:
        tx.c(f"AUTH PLAIN <credentials for {auth}>")
        tx.s("235 2.7.0 Authentication successful")

    error = None
    result = None
    tx.c(f"MAIL FROM:<{env_from}>")
    rc = code_name(m.envfrom(f"<{env_from}>"))
    tx.milter(f"envfrom(<{env_from}>) -> {rc}")
    tx.s(smtp_reply(rc, ctx.reply, "250 2.1.0 Ok"))
    if rc in ("REJECT", "TEMPFAIL"):
        result = rc

    accepted = []
    refused = []
    if result is None:
        for r in recipients:
            tx.c(f"RCPT TO:<{r}>")
            # a setreply() answers only the command it was made for
            ctx.reply = None
            rc = code_name(m.envrcpt(f"<{r}>"))
            tx.milter(f"envrcpt(<{r}>) -> {rc}")
            reply = smtp_reply(rc, ctx.reply, "250 2.1.5 Ok")
            tx.s(reply)
            if rc in ("REJECT", "TEMPFAIL"):
                refused.append({"recipient": r, "reply": reply})
            else:
                accepted.append(r)
        ctx.reply = None
        if not accepted:
            result = "REJECT"
            ctx.reply = "554 5.5.1 Error: no valid recipients"
            tx.c("DATA")
            tx.s(ctx.reply)

    if result is None:
        tx.c("DATA")
        tx.s("354 End data with <CR><LF>.<CR><LF>")
        for k, v in headers:
            tx.c(f"{k}: {v}")
            m.header(k, v)
        tx.c("", *body, ".")
        tx.milter(f"header() x{len(headers)}, eoh(), body()")
        try:
            result = code_name(m.eom())
        except Exception:
            # pymilter's default exception policy
            error = traceback.format_exc()
            result = "TEMPFAIL"
            ctx.reply = "451 4.3.0 pymilter: untrapped exception in EnvelopeMilter"
        tx.milter(f"eom() -> {result}" + ("  (untrapped exception)" if error else ""))
        for a in ctx.actions:
            tx.milter(f"{a[0]}({', '.join(repr(x) for x in a[1:])})")
        tx.s(smtp_reply(result, ctx.reply, f"250 2.0.0 Ok: queued as {QUEUE_ID}"))
        if result == "DISCARD":
            tx.note("DISCARD: accepted but silently dropped")
        elif result == "TEMPFAIL":
            tx.note("not queued; the client keeps the message and retries")
        elif result == "REJECT":
            tx.note("not queued; the client bounces the message")
    tx.c("QUIT")
    tx.s("221 2.0.0 Bye")

    final_from = env_from
    new_header_from = None
    # Postfix matches delrcpt() against the recipient exactly as it was given
    rcpts = list(accepted)
    warnings = []
    for action in ctx.actions:
        if action[0] == "chgfrom":
            final_from = action[1]
        elif action[0] == "chgheader" and action[1].lower() == "from":
            new_header_from = action[3]
        elif action[0] == "delrcpt":
            addr = email.utils.parseaddr(action[1])[1]
            if addr in rcpts:
                rcpts.remove(addr)
            else:
                warnings.append(f"delrcpt({action[1]!r}) matches no recipient exactly; "
                                f"the original stays in the message")
        elif action[0] == "addrcpt":
            rcpts.append(email.utils.parseaddr(action[1])[1])

    final_headers = apply_header_changes(headers, ctx.actions)
    if result in ("CONTINUE", "ACCEPT"):
        relay_sessions(tx, server, client, auth, final_from, rcpts,
                       final_headers, body, local_domains)

    ignored = [r for r in recipients if rewriter.internal_addr(r) in ignore_list]
    report = {
        "mode": "list fan-out" if fanout else "single message",
        "ignore_list": sorted(ignore_list),
        "ignored_recipients": ignored,
        "input": {"envelope_from": env_from, "header_from": header_from,
                  "recipients": recipients, "auth_user": auth or None},
        "result": result,
        "reply": ctx.reply,
        "refused_recipients": refused,
        "envelope_from": final_from,
        "header_from": new_header_from or header_from,
        "recipients": rcpts,
        "headers": [list(h) for h in final_headers],
        "milter_actions": [list(a) for a in ctx.actions],
        "db_writes": db.writes,
        "db_queries": [q for q, _params in db.queries],
        "dns_lookups": [list(x) for x in checks.lookups],
        "dns_queries": [list(x) for x in fake_dns.queries],
        "stubbed_modules": stubbed,
        "warnings": warnings,
        "exception": error,
    }
    if args.debug:
        report["smtp_transcript"] = tx.lines

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    def changed(before, after):
        before, after = before or "<>", after or "<>"
        return f"{before}  ->  {after}" if before != after else f"{before}  (unchanged)"

    if args.debug:
        print("\n".join(tx.lines))
    print()
    print(f"mode:           {report['mode']}" + (f" of {list_addr}" if fanout else ""))
    print(f"result:         {result}" + (f"   reply: {ctx.reply}" if ctx.reply else ""))
    print(f"envelope from:  {changed(env_from, final_from)}")
    print(f"header From:    {changed(header_from, report['header_from'])}")
    for (name, before), (_name, after) in zip(headers, final_headers):
        if name.lower() in ("to", "cc") and before != after:
            print(f"header {name + ':':<9}{changed(before, after)}")
    print("recipients:")
    refused_replies = {x["recipient"]: x["reply"] for x in refused}
    for r in recipients:
        mark = " " if r in rcpts else "-"
        note = f"   (refused at RCPT: {refused_replies[r]})" if r in refused_replies else ""
        print(f"  {mark} {r}" + ("   (on ignore list)" if r in ignored else "") + note)
    for r in rcpts:
        if r not in recipients:
            print(f"  + {r}")
    print(f"ignore list:    {', '.join(sorted(ignore_list)) or '(empty)'}")
    if db.writes:
        print("db writes:")
        for w in db.writes:
            print(f"    virtual: {w['email']} -> {w['destination']}")
    if checks.lookups:
        print("dns:")
        for kind, domain, answer in checks.lookups:
            print(f"    {kind} {domain}: {answer}")
    for w in warnings:
        print(f"warning:        {w}")
    if stubbed:
        print(f"stubbed:        {', '.join(stubbed)} (not installed)")
    if error:
        print("\nuntrapped exception in eom():\n" + error)
    return 0


if __name__ == "__main__":
    sys.exit(main())
