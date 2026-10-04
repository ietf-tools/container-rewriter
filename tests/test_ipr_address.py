"""IPR response addresses: ietf-ipr+<token>@ietf.org.

The datatracker hands out reply-to addresses with a 16-character urlsafe
base64 token.  Postfix delivers them through ietf-ipr@ietf.org, so the
rewriter must treat them as that address: ignored when ietf-ipr@ is on the
ignore list, an alias when ietf-ipr@ is in the virtual table.

Local only: the database, DMARC/SPF lookups and the Milter context are
stubbed, so nothing here leaves the process.
"""
from contextlib import nullcontext

import pytest

import harness

IPR = "ietf-ipr@ietf.org"
TOKEN = "h2NLhA7z56cuaPKQ"
ADDR = f"ietf-ipr+{TOKEN}@ietf.org"
KEY = ADDR.lower()
SENDER = "alice@yahoo.test"
FORWARDING_ADDR = harness.DEFAULT_ENV["FORWARDING_ADDR"]

# urlsafe base64 uses - and _ as well as letters and digits
TOKENS = [
    pytest.param(TOKEN, id="mixed-case"),
    pytest.param("a-b_c-d_e-f_g-h_", id="dash-underscore"),
    pytest.param("0123456789ABCDEF", id="digits-upper"),
]


class StubDB:
    """In-memory stand-in for the postfix database: get_db_pool() returns it."""

    def __init__(self, virtual=()):
        self.virtual = set(virtual)
        self.queries = []   # ("virtual", keys) for each SELECT
        self.writes = []    # (email, destination) for each wrap INSERT

    def connection(self):
        return nullcontext(self)

    def cursor(self):
        return nullcontext(self)

    def execute(self, sql, params):
        sql = " ".join(sql.split()).lower()
        if sql.startswith("insert into virtual"):
            self.writes.append(tuple(params))
            self.rows = []
            return
        # every SELECT is against the virtual table
        keys = list(params[0])
        self.queries.append(("virtual", keys))
        self.rows = [(k,) for k in keys if k in self.virtual]

    def fetchall(self):
        return self.rows


@pytest.fixture
def stub(rewriter, monkeypatch):
    """Stub every external lookup; returns a function to install a StubDB."""
    # p=reject for the sender, so anything not exempt would be rewritten
    monkeypatch.setattr(rewriter, "check_dmarc", lambda addr: True)
    monkeypatch.setattr(rewriter, "check_spf", lambda addr: False)
    monkeypatch.setattr(rewriter, "ignore_list", set())

    def install(virtual=(), ignore=()):
        db = StubDB(virtual)
        monkeypatch.setattr(rewriter, "get_db_pool", lambda: db)
        monkeypatch.setattr(rewriter, "ignore_list", rewriter.parse_ignore_list(",".join(ignore)))
        return db
    return install


def deliver(rewriter, *rcpts):
    """Run one message through EnvelopeMilter with a fake Milter context."""
    ctx = harness.FakeCtx({"i": "TEST01", "{auth_authen}": None})
    m = rewriter.EnvelopeMilter()
    if hasattr(m, "_setctx"):
        m._setctx(ctx)
    m._ctx = ctx
    m._actions = rewriter.Milter.CURR_ACTS
    assert m.envfrom(f"<{SENDER}>") == rewriter.Milter.CONTINUE
    for rcpt in rcpts:
        assert m.envrcpt(f"<{rcpt}>") == rewriter.Milter.CONTINUE
    m.header("From", SENDER)
    m.header("To", rcpts[0])
    return m.eom(), ctx, m


# --- address helpers -----------------------------------------------------------

@pytest.mark.parametrize("token", TOKENS)
def test_lookup_keys_strip_token(rewriter, token):
    key = rewriter.internal_addr(f"ietf-ipr+{token}@ietf.org")
    assert key == f"ietf-ipr+{token.lower()}@ietf.org"
    # the order Postfix uses: the full address, then without the extension
    assert rewriter.lookup_keys(key) == [key, IPR]


def test_not_wrapped_or_list_bounce(rewriter):
    assert not rewriter.is_wrapped(ADDR)
    assert not rewriter.listbounce_mailmatch.search(ADDR)


@pytest.mark.parametrize("ignore, expected", [
    pytest.param({IPR}, True, id="base-address-entry"),
    pytest.param({KEY}, True, id="exact-entry"),
    pytest.param({"ietf-ipr+othertoken0000@ietf.org"}, False, id="other-token-entry"),
    pytest.param({"ipr@ietf.org"}, False, id="different-alias"),
    pytest.param(set(), False, id="empty"),
])
def test_is_ignored(rewriter, monkeypatch, ignore, expected):
    monkeypatch.setattr(rewriter, "ignore_list", ignore)
    assert rewriter.is_ignored(KEY) is expected


# --- the milter ----------------------------------------------------------------

@pytest.mark.parametrize("token", TOKENS)
def test_ignored_ipr_reply_untouched(rewriter, stub, token):
    db = stub(virtual={IPR}, ignore=[IPR])
    addr = f"ietf-ipr+{token}@ietf.org"
    rc, ctx, m = deliver(rewriter, addr)
    assert rc == rewriter.Milter.ACCEPT
    assert ctx.actions == []          # no chgfrom, chgheader, addheader or rcpt changes
    assert db.writes == []            # no wrap recorded for the sender
    assert m.mail_to == [addr]        # the token keeps its case


def test_rcpt_needs_no_database(rewriter, stub):
    # not a wrapped address, so envrcpt() accepts it without a lookup
    db = stub(virtual={IPR}, ignore=[IPR])
    m = rewriter.EnvelopeMilter()
    ctx = harness.FakeCtx({})
    if hasattr(m, "_setctx"):
        m._setctx(ctx)
    m._ctx = ctx
    m.envfrom(f"<{SENDER}>")
    assert m.envrcpt(f"<{ADDR}>") == rewriter.Milter.CONTINUE
    assert db.queries == []


def test_not_ignored_ipr_reply_is_the_alias(rewriter, stub):
    """Without the ignore entry, ietf-ipr+<token>@ is found as the ietf-ipr@
    alias, as Postfix expands it, and is rewritten on the alias path."""
    db = stub(virtual={IPR})
    rc, ctx, m = deliver(rewriter, ADDR)
    assert rc == rewriter.Milter.ACCEPT
    assert ("virtual", [KEY, IPR]) in db.queries
    assert ("chgfrom", FORWARDING_ADDR) in ctx.actions
    assert [a for a in ctx.actions if a[:2] == ("chgheader", "From")]
    assert db.writes == [("alice=40yahoo.test@dmarc.ietf.org", SENDER)]
    assert m.mail_to == [ADDR]        # the recipient itself is never changed


def test_ignored_ipr_reply_beside_list_untouched(rewriter, stub):
    stub(virtual={IPR}, ignore=[IPR])
    rc, ctx, _ = deliver(rewriter, ADDR, "ietf@ietf.org")
    assert rc == rewriter.Milter.ACCEPT
    assert ctx.actions == []
