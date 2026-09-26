"""Edge cases for wrapping sender addresses and unwrapping replies.

Wrapping turns local@domain into local=40domain@FORWARDING_DOMAIN, quoting
the new local part only when it isn't a dot-atom (RFC 5321/5322).  The
database key is Postfix's internal form: unquoted and lowercased.
Unwrapping a reply must give back the original sender.
"""
import email.utils
from email.headerregistry import Address

import pytest

FWD = "dmarc.ietf.org"
SENDER = "bob@other.test"


def domain_of(addr):
    return addr.rpartition("@")[2].lower()


# (original sender, wrapped address, database key, address a reply unwraps to)
CASES = [
    pytest.param("alice@example.com",
                 f"alice=40example.com@{FWD}",
                 f"alice=40example.com@{FWD}",
                 "alice@example.com", id="plain"),
    pytest.param("Alice.Smith@Example.COM",
                 f"Alice.Smith=40example.com@{FWD}",
                 f"alice.smith=40example.com@{FWD}",
                 "Alice.Smith@example.com", id="mixed-case"),
    pytest.param("user+tag@example.com",
                 f"user+tag=40example.com@{FWD}",
                 f"user+tag=40example.com@{FWD}",
                 "user+tag@example.com", id="plus-tag"),
    pytest.param("o'brien@example.com",
                 f"o'brien=40example.com@{FWD}",
                 f"o'brien=40example.com@{FWD}",
                 "o'brien@example.com", id="apostrophe"),
    pytest.param("!#$%&*/=?^_`{|}~-@example.com",
                 f"!#$%&*/=?^_`{{|}}~-=40example.com@{FWD}",
                 f"!#$%&*/=?^_`{{|}}~-=40example.com@{FWD}",
                 "!#$%&*/=?^_`{|}~-@example.com", id="all-atext"),
    pytest.param("first.last@mail.sub.example.co.uk",
                 f"first.last=40mail.sub.example.co.uk@{FWD}",
                 f"first.last=40mail.sub.example.co.uk@{FWD}",
                 "first.last@mail.sub.example.co.uk", id="deep-domain"),
    pytest.param('"john smith"@example.com',
                 f'"john smith=40example.com"@{FWD}',
                 f"john smith=40example.com@{FWD}",
                 '"john smith"@example.com', id="quoted-space"),
    pytest.param('"a..b"@example.com',
                 f'"a..b=40example.com"@{FWD}',
                 f"a..b=40example.com@{FWD}",
                 '"a..b"@example.com', id="quoted-double-dot"),
    pytest.param('".alice"@example.com',
                 f'".alice=40example.com"@{FWD}',
                 f".alice=40example.com@{FWD}",
                 '".alice"@example.com', id="quoted-leading-dot"),
    # the trailing dot is followed by =40domain once wrapped, so no quotes
    pytest.param('"alice."@example.com',
                 f"alice.=40example.com@{FWD}",
                 f"alice.=40example.com@{FWD}",
                 '"alice."@example.com', id="quoted-trailing-dot"),
    pytest.param('"j\\"q"@example.com',
                 f'"j\\"q=40example.com"@{FWD}',
                 f'j"q=40example.com@{FWD}',
                 '"j\\"q"@example.com', id="escaped-quote"),
    pytest.param('"back\\\\slash"@example.com',
                 f'"back\\\\slash=40example.com"@{FWD}',
                 f"back\\slash=40example.com@{FWD}",
                 '"back\\\\slash"@example.com', id="escaped-backslash"),
    pytest.param('"with,comma"@example.com',
                 f'"with,comma=40example.com"@{FWD}',
                 f"with,comma=40example.com@{FWD}",
                 '"with,comma"@example.com', id="quoted-comma"),
    pytest.param('"a@b"@example.com',
                 f'"a@b=40example.com"@{FWD}',
                 f"a@b=40example.com@{FWD}",
                 '"a@b"@example.com', id="quoted-at-sign"),
    pytest.param('"plain"@example.com',
                 f"plain=40example.com@{FWD}",
                 f"plain=40example.com@{FWD}",
                 "plain@example.com", id="needless-quotes"),
    # wrapped again by us: only the last =40 is split off when unwrapping
    pytest.param("bob=40other.test@example.com",
                 f"bob=40other.test=40example.com@{FWD}",
                 f"bob=40other.test=40example.com@{FWD}",
                 "bob=40other.test@example.com", id="already-wrapped"),
    pytest.param("josé@exämple.com",
                 f"josé=40exämple.com@{FWD}",
                 f"josé=40exämple.com@{FWD}",
                 "josé@exämple.com", id="utf8"),
    pytest.param("x" * 60 + "@example.com",
                 "x" * 60 + f"=40example.com@{FWD}",
                 "x" * 60 + f"=40example.com@{FWD}",
                 "x" * 60 + "@example.com", id="long-local"),
    pytest.param("noreply-bounce@example.com",
                 f"noreply-bounce=40example.com@{FWD}",
                 f"noreply-bounce=40example.com@{FWD}",
                 "noreply-bounce@example.com", id="ends-in-bounce"),
]


# --- the helpers on their own -------------------------------------------------

@pytest.mark.parametrize("local, quoted", [
    ("alice", "alice"),
    ("first.last", "first.last"),
    ("o'brien", "o'brien"),
    ("user+tag", "user+tag"),
    ("josé", "josé"),
    ("john smith", '"john smith"'),
    ("a..b", '"a..b"'),
    (".alice", '".alice"'),
    ("alice.", '"alice."'),
    ('j"q', '"j\\"q"'),
    ("back\\slash", '"back\\\\slash"'),
    ("a@b", '"a@b"'),
    ("with,comma", '"with,comma"'),
    ("", '""'),
])
def test_quote_local(rewriter, local, quoted):
    assert rewriter.quote_local(local) == quoted
    assert rewriter.unquote_local(quoted) == local


@pytest.mark.parametrize("original, wrapped, key, unwrapped", CASES)
def test_wrap_addr(rewriter, original, wrapped, key, unwrapped):
    assert rewriter.wrap_addr(original, FWD) == wrapped
    assert rewriter.internal_addr(wrapped) == key
    assert rewriter.unwrap_addr(wrapped) == unwrapped


@pytest.mark.parametrize("original, wrapped, key, unwrapped", [
    c for c in CASES if c.values[1].isascii()])
def test_wrapped_is_valid_addr_spec(original, wrapped, key, unwrapped):
    # the email package rejects addr-specs with syntax defects
    Address(addr_spec=wrapped)


# --- through the milter -------------------------------------------------------

@pytest.mark.parametrize("original, wrapped, key, unwrapped", CASES)
def test_wrap_through_milter(rewriter, run, original, wrapped, key, unwrapped):
    report = run("--from", original, "--to", "carol@elsewhere.test",
                 "--dmarc", f"{domain_of(original)}=reject")
    assert report["result"] == "ACCEPT"
    assert report["header_from"] == wrapped
    assert report["envelope_from"] == wrapped
    # both columns hold Postfix's internal form: unquoted and lowercased
    assert report["db_writes"] == [{"table": "virtual", "email": key,
                                    "destination": rewriter.internal_addr(original)}]


@pytest.mark.parametrize("original, wrapped, key, unwrapped", CASES)
def test_reply_unwraps_to_sender(run, original, wrapped, key, unwrapped):
    report = run("--from", SENDER, "--to", wrapped, "--virtual", key)
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == [unwrapped]
    assert report["warnings"] == []


@pytest.mark.parametrize("original, wrapped, key, unwrapped", CASES)
def test_round_trip(run, original, wrapped, key, unwrapped):
    """Wrap a sender, then reply to the header From the milter produced."""
    out = run("--from", original, "--to", "carol@elsewhere.test",
              "--dmarc", f"{domain_of(original)}=reject")
    reply_to = email.utils.parseaddr(out["header_from"])[1]
    stored = out["db_writes"][0]["email"]
    back = run("--from", SENDER, "--to", reply_to, "--virtual", stored)
    assert back["recipients"] == [unwrapped]


# --- recipients that look wrapped but aren't ------------------------------------

@pytest.mark.parametrize("rcpt", [
    pytest.param(f"alice@{FWD}", id="no-separator"),
    pytest.param("alice=40example.com@other.test", id="other-domain"),
    pytest.param(f"alice=40example.com@x{FWD}", id="domain-prefix"),
    pytest.param(f"alice=40example.com@{FWD}.evil.test", id="domain-suffix"),
    pytest.param("alice=40example.com@dmarcXietf.org", id="dot-is-literal"),
    pytest.param(f"alice=40@{FWD}", id="empty-original-domain"),
    pytest.param(f"=40example.com@{FWD}", id="empty-user"),
    pytest.param(f"alice=40exa_mple.com@{FWD}", id="bad-domain-char"),
])
def test_not_unwrapped(run, rcpt):
    report = run("--from", SENDER, "--to", rcpt, "--virtual", rcpt.lower())
    assert report["recipients"] == [rcpt]
    assert not [a for a in report["milter_actions"] if a[0] in ("delrcpt", "addrcpt")]


@pytest.mark.parametrize("rcpt, key, unwrapped", [
    pytest.param(f"ALICE=40EXAMPLE.COM@{FWD.upper()}", f"alice=40example.com@{FWD}",
                 "ALICE@EXAMPLE.COM", id="upper-case"),
    pytest.param(f'"John Smith=40Example.com"@{FWD}', f"john smith=40example.com@{FWD}",
                 '"John Smith"@Example.com', id="quoted-mixed-case"),
    pytest.param(f"ietf-bounces=40ietf.org@{FWD}", None,
                 "ietf-bounces@ietf.org", id="list-bounce"),
])
def test_unwrap_recipient_forms(run, rcpt, key, unwrapped):
    args = ["--from", SENDER, "--to", rcpt]
    if key:
        args += ["--virtual", key]
    report = run(*args)
    assert report["recipients"] == [unwrapped]
    assert report["warnings"] == []
