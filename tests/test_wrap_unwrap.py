"""Edge cases for wrapping sender addresses and unwrapping replies.

Wrapping turns local@domain into local=40domain@FORWARDING_DOMAIN, quoting
the new local part only when it isn't a dot-atom (RFC 5321/5322).  The
database key is Postfix's internal form: unquoted and lowercased.
Unwrapping a reply must give back the original sender.
"""
import email.utils
from email.headerregistry import Address

import pytest

import harness

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


# --- replies delivered to the wrapped addresses in To: and Cc: --------------------

def header_values(report, name):
    return [v for k, v in report["headers"] if k.lower() == name.lower()]


@pytest.mark.parametrize("value, expected", [
    pytest.param(f"alice=40example.com@{FWD}", "alice@example.com", id="bare"),
    pytest.param(f"Alice Smith <alice=40example.com@{FWD}>",
                 "Alice Smith <alice@example.com>", id="display-name"),
    pytest.param(f'"Smith, Alice" <alice=40example.com@{FWD}>, carol@elsewhere.test',
                 '"Smith, Alice" <alice@example.com>, carol@elsewhere.test', id="with-other"),
    pytest.param(f"=?utf-8?q?Jos=C3=A9?= <jose=40example.com@{FWD}>",
                 "=?utf-8?b?Sm9zw6k=?= <jose@example.com>", id="encoded-name"),
    pytest.param(f"a=40x.test@{FWD},\r\n\tb=40y.test@{FWD}", "a@x.test, b@y.test", id="folded-input"),
    pytest.param(", ".join(f"user{i}=40example.com@{FWD}" for i in range(6)),
                 "user0@example.com, user1@example.com, user2@example.com, user3@example.com,\n\t"
                 "user4@example.com, user5@example.com", id="long-is-folded"),
    pytest.param("carol@elsewhere.test, dave@other.test", None, id="none-wrapped"),
    pytest.param("undisclosed-recipients:;", None, id="empty-group"),
])
def test_unwrap_header_addrs(rewriter, value, expected):
    assert rewriter.unwrap_header_addrs(value) == expected


@pytest.mark.parametrize("original, wrapped, key, unwrapped", CASES)
def test_reply_unwraps_to_header(run, original, wrapped, key, unwrapped):
    report = run("--from", SENDER, "--to", wrapped, "--virtual", key)
    assert header_values(report, "To") == [unwrapped]


def test_cc_wraps_unwrapped_but_not_added(run):
    """A wrap only in Cc: is shown unwrapped, but only the envelope's wraps
    are delivered to; the sender's server sends every wrap it means to."""
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}",
                 "--header", f"Cc: Bob <bob=40other.test@{FWD}>, carol@elsewhere.test",
                 "--virtual", f"alice=40example.com@{FWD}", "--virtual", f"bob=40other.test@{FWD}")
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["alice@example.com"]
    assert header_values(report, "To") == ["alice@example.com"]
    assert header_values(report, "Cc") == ["Bob <bob@other.test>, carol@elsewhere.test"]


def test_header_wraps_do_not_fan_out(run):
    """One wrapped envelope recipient can't reach every valid wrap listed in
    the headers."""
    wraps = [f"v{i}=40example{i}.test@{FWD}" for i in range(5)]
    report = run("--from", SENDER, "--to", wraps[0], "--header", "Cc: " + ", ".join(wraps[1:]),
                 *[arg for w in wraps for arg in ("--virtual", w)])
    assert report["recipients"] == ["v0@example0.test"]


def test_unknown_wraps_in_headers_not_delivered(run):
    """Only wraps we handed out may be delivered to; the rest are only shown
    unwrapped in the headers."""
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}",
                 "--header", f"Cc: mallory=40evil.test@{FWD}",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert report["recipients"] == ["alice@example.com"]
    assert header_values(report, "Cc") == ["mallory@evil.test"]


def refused(report):
    return {x["recipient"]: x["reply"] for x in report["refused_recipients"]}


def test_bcc_wrapped_recipient_delivered(run):
    """Unlike postconfirm, a wrapped address only in the envelope still gets
    its copy: once accepted, a recipient must not be lost (RFC 5321 6.1)."""
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}",
                 "--bcc", f"bcc=40example.org@{FWD}",
                 "--virtual", f"alice=40example.com@{FWD}", "--virtual", f"bcc=40example.org@{FWD}")
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["alice@example.com", "bcc@example.org"]
    assert report["warnings"] == []


def test_unknown_wrap_refused_at_rcpt(run):
    """Only the unknown wrapped recipient is refused; the rest are delivered."""
    nobody = f"nobody=40example.com@{FWD}"
    report = run("--from", SENDER, "--to", "carol@elsewhere.test", nobody,
                 "--bcc", f"bcc=40example.org@{FWD}", "--virtual", f"bcc=40example.org@{FWD}")
    assert refused(report) == {nobody: "550 5.1.1 unknown wrapped address"}
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["carol@elsewhere.test", "bcc@example.org"]
    # the refused address was never accepted, so it isn't deleted later
    assert ["delrcpt", nobody] not in report["milter_actions"]


def test_only_unknown_wraps_refuses_message(run):
    nobody = f"nobody=40example.com@{FWD}"
    report = run("--from", SENDER, "--to", nobody)
    assert refused(report) == {nobody: "550 5.1.1 unknown wrapped address"}
    assert report["result"] == "REJECT"
    assert report["reply"] == "554 5.5.1 Error: no valid recipients"


def test_duplicate_addresses_delivered_once(run):
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}",
                 "--header", f"Cc: ALICE=40EXAMPLE.COM@{FWD}, Alice <alice=40example.com@{FWD}>",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert report["recipients"] == ["alice@example.com"]


def test_original_also_on_envelope_delivered_once(run):
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}", "alice@example.com",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert report["recipients"] == ["alice@example.com"]


def test_every_to_and_cc_header_is_rewritten(run):
    report = run("--from", SENDER, "--to", f"alice=40example.com@{FWD}",
                 "--header", f"Cc: Bob <bob=40other.test@{FWD}>",
                 "--header", "Cc: carol@elsewhere.test",
                 "--header", f"Cc: dave=40example.net@{FWD}",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert header_values(report, "Cc") == ["Bob <bob@other.test>", "carol@elsewhere.test",
                                           "dave@example.net"]
    assert [a[:3] for a in report["milter_actions"] if a[0] == "chgheader"] == [
        ["chgheader", "To", 1], ["chgheader", "Cc", 1], ["chgheader", "Cc", 3]]


def test_reply_all_to_list_keeps_list(run):
    report = run("--from", SENDER, "--to", "ietf@ietf.org", f"alice=40example.com@{FWD}",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["ietf@ietf.org", "alice@example.com"]
    assert header_values(report, "To") == ["ietf@ietf.org, alice@example.com"]


def test_headers_untouched_without_wrapped_recipient(run):
    """Only a message to a wrapped envelope recipient has its headers unwrapped."""
    report = run("--from", SENDER, "--to", "carol@elsewhere.test",
                 "--header", f"Cc: alice=40example.com@{FWD}")
    assert header_values(report, "Cc") == [f"alice=40example.com@{FWD}"]
    assert report["recipients"] == ["carol@elsewhere.test"]
    assert not [a for a in report["milter_actions"] if a[0] == "chgheader"]


# --- replies are DMARC-rewritten like any other forwarded message -----------------

ALICE = f"alice=40example.com@{FWD}"
FORWARDING_ADDR = f"forwardingalgorithm@{FWD}"


def test_reply_from_reject_domain_is_rewritten(run):
    report = run("--from", "Bob <bob@yahoo.test>", "--dmarc", "yahoo.test=reject",
                 "--to", ALICE, "--virtual", ALICE)
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["alice@example.com"]
    assert report["header_from"] == f"Bob <bob=40yahoo.test@{FWD}>"
    assert report["envelope_from"] == FORWARDING_ADDR
    assert ["addheader", "X-Original-From", "Bob <bob@yahoo.test>"] in report["milter_actions"]
    # so that alice can reply back through the wrap
    assert report["db_writes"] == [{"table": "virtual", "email": f"bob=40yahoo.test@{FWD}",
                                    "destination": "bob@yahoo.test"}]


def test_reply_round_trip(run):
    """Bob replies to alice's wrap, then alice replies to bob's."""
    bob = run("--from", "bob@yahoo.test", "--dmarc", "yahoo.test=reject",
              "--to", ALICE, "--virtual", ALICE)
    bob_wrapped = email.utils.parseaddr(bob["header_from"])[1]
    alice = run("--from", "alice@example.com", "--dmarc", "example.com=reject",
                "--to", bob_wrapped, "--virtual", bob["db_writes"][0]["email"])
    assert alice["recipients"] == ["bob@yahoo.test"]
    assert alice["header_from"] == ALICE


def test_reply_from_no_policy_domain_untouched(run):
    report = run("--from", SENDER, "--to", ALICE, "--virtual", ALICE)
    assert report["header_from"] == SENDER
    assert report["envelope_from"] == SENDER
    assert report["db_writes"] == []


def test_reply_spf_only_rewrites_envelope(run):
    report = run("-f", "bounces@mailer.example.net", "--from", SENDER,
                 "--spf", "mailer.example.net=-all", "--to", ALICE, "--virtual", ALICE)
    assert report["header_from"] == SENDER
    assert report["envelope_from"] == FORWARDING_ADDR


def test_reply_from_local_sender_untouched(run):
    report = run("--from", "staff@ietf.org", "--to", ALICE, "--virtual", ALICE)
    assert report["header_from"] == "staff@ietf.org"
    assert report["envelope_from"] == "staff@ietf.org"


def test_bounce_to_wrapped_address(run):
    """A DSN keeps its null sender and gets no wrap record."""
    report = run("-f", "", "--from", "MAILER-DAEMON@yahoo.test", "--dmarc", "yahoo.test=reject",
                 "--to", ALICE, "--virtual", ALICE)
    assert report["header_from"] == f"MAILER-DAEMON=40yahoo.test@{FWD}"
    assert report["envelope_from"] == ""
    assert report["db_writes"] == []


def test_reply_all_to_list_rewrites_from(run):
    """The list's copy shares the transaction with the unwrapped reply, which
    must pass DMARC, so the From is rewritten for both; Postfix's
    lmtp_generic_maps restores it on the copy delivered to mailman."""
    report = run("--from", "bob@yahoo.test", "--dmarc", "yahoo.test=reject",
                 "--to", "ietf@ietf.org", ALICE, "--virtual", ALICE)
    assert report["recipients"] == ["ietf@ietf.org", "alice@example.com"]
    assert report["header_from"] == f"bob=40yahoo.test@{FWD}"
    assert report["envelope_from"] == harness.DEFAULT_ENV["FORWARDING_ADDR"]


def test_reply_with_ignored_recipient_rewrites_from(run):
    """An ignore-list recipient alongside a wrapped one must not leave the
    unwrapped copy with a From that fails DMARC."""
    report = run("--from", "bob@yahoo.test", "--dmarc", "yahoo.test=reject",
                 "--to", ALICE, "ignored@lists.test", "--virtual", ALICE,
                 "--ignore", "ignored@lists.test")
    assert "alice@example.com" in report["recipients"]
    assert report["header_from"] == f"bob=40yahoo.test@{FWD}"


def test_reply_to_duplicate_wrap_left_to_usual_checks(run):
    """A wrap of a recipient already on the message adds no one, so scenario 1
    doesn't decide; alice is then an off-site recipient alongside the list."""
    report = run("--from", "bob@yahoo.test", "--dmarc", "yahoo.test=reject",
                 "--to", "ietf@ietf.org", ALICE, "alice@example.com",
                 "--virtual", ALICE)
    assert report["recipients"] == ["ietf@ietf.org", "alice@example.com"]
    assert report["header_from"] == f"bob=40yahoo.test@{FWD}"


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
