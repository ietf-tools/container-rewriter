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

No database is contacted.  DNS lookups are real unless --no-dns is given;
--dmarc/--spf pin a domain's answer either way.  Configuration comes from the
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

# always present in mailman_lists, so test_local_list() matches them
DEFAULT_LOCAL_LISTS = ("ietf@ietf.org", "testlist@ietf.org")


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


def _stub_checkdmarc():
    mod = types.ModuleType("checkdmarc")

    def unavailable(domain, **kw):
        return {"error": "checkdmarc not installed (harness stub)"}
    mod.check_dmarc = mod.check_spf = unavailable
    return mod


def install_stubs():
    stubbed = []
    for name, factory in (("Milter", _stub_milter),
                          ("expiringdict", _stub_expiringdict),
                          ("checkdmarc", _stub_checkdmarc)):
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

    def __init__(self, lists, virtual, down):
        self.lists = set(lists)
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
        if "from mailman_lists" in q:
            self.rows = [(a,) for a in params[0] if a in self.db.lists]
        elif "from virtual" in q and "any(" in q:
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


# --- fake DNS policy ---------------------------------------------------------

DNS_FAILURES = {
    "timeout": "The resolution lifetime expired after 1.000 seconds: "
               "Server 192.0.2.1 answered The DNS operation timed out.",
    "timeout-empty": "The resolution lifetime expired after 1.000 seconds: ",
    "servfail": "All nameservers failed to answer the query: Server 192.0.2.1 answered SERVFAIL",
    "nxdomain": "The domain does not exist.",
}


SPF_ALL = {"-all": "fail", "~all": "softfail", "?all": "neutral", "+all": "pass", "all": "pass"}


class FakeCheckdmarc:
    """Proxy for the checkdmarc module that serves pinned answers first."""

    def __init__(self, real, dmarc, spf, no_dns):
        self.real, self.dmarc, self.spf, self.no_dns = real, dmarc, spf, no_dns
        self.lookups = []

    def _answer(self, kind, domain, pinned, ok, real_fn, kw, walk=False):
        # walk: like checkdmarc's DMARC tree walk, an unpinned domain takes
        # the answer pinned on its nearest parent (never a bare TLD)
        location, value = domain, pinned.get(domain)
        if value is None and walk:
            labels = domain.split(".")
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                if parent in pinned:
                    location, value = parent, pinned[parent]
                    break
        if value is None and self.no_dns:
            value = "nxdomain"
        if value is None:
            self.lookups.append((kind, domain, "live DNS"))
            return real_fn(domain, **kw)
        self.lookups.append((kind, domain, value if location == domain else f"{value} (at {location})"))
        if value in DNS_FAILURES:
            return {"error": DNS_FAILURES[value]}
        return ok(value, location)

    def check_dmarc(self, domain, **kw):
        return self._answer("dmarc", domain, self.dmarc, dmarc_result,
                            self.real.check_dmarc, kw, walk=True)

    def check_spf(self, domain, **kw):
        # checkdmarc reports the "all" mechanism by result name, not qualifier
        return self._answer("spf", domain, self.spf,
                            lambda v, _loc: {"parsed": {"all": SPF_ALL.get(v, v)}},
                            self.real.check_spf, kw)


def dmarc_result(value, location):
    """checkdmarc's result for a pinned policy: 'reject' or 'p=none;sp=reject'."""
    tags = {}
    for part in value.split(";"):
        tag, sep, v = part.strip().partition("=")
        if part.strip():
            tags[tag if sep else "p"] = v if sep else tag
    if "p" not in tags:
        sys.exit(f"--dmarc policy {value!r} has no p= tag")
    tags.setdefault("sp", tags["p"])
    return {"location": location, "valid": True,
            "tags": {t: {"value": v, "explicit": True} for t, v in tags.items()}}


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
        pins[domain.lower()] = answer.lower()
    return pins


def build_parser():
    p = argparse.ArgumentParser(
        description="Run one message through rewriter.py's milter logic offline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"DNS answers for --dmarc/--spf: a policy (reject, quarantine, none, or tags such as "
               f"'p=none;sp=reject' / -all, ~all, ?all, +all or fail, softfail, neutral, pass) "
               f"or a failure ({', '.join(DNS_FAILURES)}). A --dmarc answer also covers the "
               f"domain's subdomains, as a parent record would.")
    p.add_argument("--from", dest="source", default="sender@example.com",
                   help="From header, e.g. 'Alice <alice@yahoo.com>' (default: %(default)s)")
    p.add_argument("--to", nargs="+", default=None,
                   help="destination address(es); required unless --list is given "
                        "(then defaults to the --list address)")
    p.add_argument("--list", default=None, metavar="ADDR",
                   help="treat the message as a mailman fan-out from this list")
    p.add_argument("-f", "--env-from", "--mail-from", dest="env_from", metavar="ADDR",
                   help="envelope sender (MAIL FROM); default: the --from address, or "
                        "<list>-bounces@<domain> for a fan-out. Use '' for the null sender <>")
    p.add_argument("--auth", help="override the SASL user ({auth_authen})")
    p.add_argument("--local-list", action="append", default=[], metavar="ADDR",
                   help="extra address in mailman_lists (the --list address and "
                        f"{', '.join(DEFAULT_LOCAL_LISTS)} are always there)")
    p.add_argument("--no-default-lists", action="store_true",
                   help=f"leave {', '.join(DEFAULT_LOCAL_LISTS)} out of mailman_lists")
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
    if args.ignore is not None:
        os.environ["IGNORELIST"] = ",".join(args.ignore)
    os.environ["LOG_LEVEL"] = "DEBUG" if args.verbose else ("WARNING" if args.quiet else "INFO")
    log_dir = tempfile.mkdtemp(prefix="rewriter-harness-")
    os.environ["LOGGING_FILENAME"] = os.path.join(log_dir, "rewrite.log")

    stubbed = install_stubs()
    sys.path.insert(0, HERE)
    import rewriter
    import Milter

    fake_dns = FakeCheckdmarc(rewriter.checkdmarc,
                              parse_pins(args.dmarc, "--dmarc"),
                              parse_pins(args.spf, "--spf"),
                              args.no_dns or "checkdmarc" in stubbed)
    rewriter.checkdmarc = fake_dns

    fanout = args.list is not None
    list_addr = args.list.lower() if fanout else None
    if fanout:
        list_local, list_domain = list_addr.rsplit("@", 1)
    elif not args.to:
        build_parser().error("--to is required unless --list is given")
    local_lists = {*(() if args.no_default_lists else DEFAULT_LOCAL_LISTS),
                   *([list_addr] if fanout else []),
                   *(a.lower() for a in args.local_list)}
    db = FakeDB(lists=local_lists,
                virtual=(a.lower() for a in args.virtual),
                down=args.db_down)
    rewriter.get_db_pool = lambda: db
    ignore_list = {a.strip().lower() for a in rewriter.ignore_list if a.strip()}

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
    if fanout:
        headers.append(("List-Id", f"<{list_local}.{list_domain}>"))
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

    if result is None:
        accepted = []
        for r in recipients:
            tx.c(f"RCPT TO:<{r}>")
            rc = code_name(m.envrcpt(f"<{r}>"))
            tx.milter(f"envrcpt(<{r}>) -> {rc}")
            tx.s(smtp_reply(rc, ctx.reply, "250 2.1.5 Ok"))
            if rc not in ("REJECT", "TEMPFAIL"):
                accepted.append(r)
        if not accepted:
            result = "REJECT"
            tx.c("DATA")
            tx.s("554 5.5.1 Error: no valid recipients")

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
    rcpts = list(recipients)
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

    if result in ("CONTINUE", "ACCEPT"):
        relay_sessions(tx, server, client, auth, final_from, rcpts,
                       apply_header_changes(headers, ctx.actions), body, local_domains)

    ignored = [r for r in recipients if r.lower() in ignore_list]
    report = {
        "mode": "list fan-out" if fanout else "single message",
        "ignore_list": sorted(ignore_list),
        "ignored_recipients": ignored,
        "input": {"envelope_from": env_from, "header_from": header_from,
                  "recipients": recipients, "auth_user": auth or None},
        "result": result,
        "reply": ctx.reply,
        "envelope_from": final_from,
        "header_from": new_header_from or header_from,
        "recipients": rcpts,
        "milter_actions": [list(a) for a in ctx.actions],
        "db_writes": db.writes,
        "dns_lookups": [list(x) for x in fake_dns.lookups],
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
    print("recipients:")
    for r in recipients:
        mark = " " if r in rcpts else "-"
        print(f"  {mark} {r}" + ("   (on ignore list)" if r in ignored else ""))
    for r in rcpts:
        if r not in recipients:
            print(f"  + {r}")
    print(f"ignore list:    {', '.join(sorted(ignore_list)) or '(empty)'}")
    if db.writes:
        print("db writes:")
        for w in db.writes:
            print(f"    virtual: {w['email']} -> {w['destination']}")
    if fake_dns.lookups:
        print("dns:            " + ", ".join(f"{k} {d}={a}" for k, d, a in fake_dns.lookups))
    for w in warnings:
        print(f"warning:        {w}")
    if stubbed:
        print(f"stubbed:        {', '.join(stubbed)} (not installed)")
    if error:
        print("\nuntrapped exception in eom():\n" + error)
    return 0


if __name__ == "__main__":
    sys.exit(main())
