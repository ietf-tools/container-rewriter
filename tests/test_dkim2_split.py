"""Split-then-sign (docs/superpowers/specs/2026-11-15-dkim2-split-then-sign-design.md).

With DKIM2_SIGN_DAEMON set, the milter has two modes, chosen per
connection from Postfix's {daemon_name} macro.  Normal mode (every
listener but the signing one) verifies, rewrites and records, and never
signs.  Sign mode (the loopback listener Postfix sends each off-site copy
to, one recipient at a time) only signs."""
import base64

import pytest

import dkim2hop
import harness
from test_dkim2_milter import (AUTHOR, BODY, BOUNCES, FOOTER, LIST, MAILMAN,  # noqa: F401
                               SUBSCRIBER, T, UNSIGNED, WRAPPED, Ctx, Sent, author_post,
                               dkim2, fields, keys, through_mailman, verified, versions)

SIGN = "DKIM2-SIGN"
OTHER = "other@example.org"


@pytest.fixture
def split(dkim2, monkeypatch):
    monkeypatch.setattr(dkim2, "dkim2_sign_daemon", SIGN)
    return dkim2


def send(rewriter, header_fields, body, mail_from, rcpts, auth=None, daemon=None):
    """One message through the milter, from the listener named daemon."""
    ctx = Ctx({"i": "TEST01", "{auth_authen}": auth, "{daemon_name}": daemon})
    m = rewriter.EnvelopeMilter()
    m._ctx = ctx
    if hasattr(m, "_setctx"):
        m._setctx(ctx)
    m._actions = rewriter.Milter.CURR_ACTS
    m.envfrom(f"<{mail_from}>")
    for r in rcpts:
        m.envrcpt(f"<{r}>")
    for field in header_fields:
        name, value = field.split(b":", 1)
        m.header(name.decode(), value.strip().replace(b"\r\n", b"\n").decode("utf-8", "surrogateescape"))
    m.eoh()
    for i in range(0, len(body), 5):
        m.body(body[i:i + 5])
    result = m.eom()
    return Sent(result, ctx.actions, header_fields, body, mail_from, rcpts)


def resend(rewriter, sent, rcpt, daemon=SIGN):
    """A copy of what pass 1 sent, for one recipient, through pass 2."""
    return send(rewriter, sent.fields, sent.body, sent.mail_from, [rcpt], daemon=daemon)


def rt(sent):
    return [base64.b64decode(x).decode() for x in sent.tag("DKIM2-Signature", "rt").split(",")]


def fanout(split, keys):
    """A list post with a footer, through mailman and pass 1."""
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    return send(split, out, body, BOUNCES, [SUBSCRIBER, OTHER], auth=MAILMAN, daemon="ORIGINATING")


# --- normal mode --------------------------------------------------------------------

def test_normal_mode_rewrites_and_records_but_never_signs(split, keys):
    sent = fanout(split, keys)
    assert sent.result == split.Milter.ACCEPT
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert sent.mail_from != BOUNCES
    # example.com's signature only; ours is left to pass 2
    assert len(sent.named("DKIM2-Signature")) == 1
    assert versions(sent) == ["3", "2", "1"]


def test_normal_mode_marks_a_list_fanout_as_exploded(split, keys):
    sent = fanout(split, keys)
    assert sent.value("X-DKIM2-Exploded") == "yes"


def test_normal_mode_keeps_mailmans_exploded_mark(split, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    out = fields(("X-DKIM2-Exploded", "yes")) + out
    sent = send(split, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN, daemon="ORIGINATING")
    assert len(sent.named("X-DKIM2-Exploded")) == 1


def test_mail_that_is_not_a_fanout_is_not_marked(split, keys):
    sent = send(split, author_post(keys), BODY, AUTHOR, [LIST], daemon="mx.ietf.org")
    assert sent.named("X-DKIM2-Exploded") == []
    assert sent.value("X-DKIM2-Arrival") == "pass"


@pytest.mark.parametrize("daemon", [None, "mx.ietf.org", "dkim2-sign", "DKIM2-SIGN2"])
def test_any_other_daemon_name_is_normal_mode(split, keys, daemon):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(split, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN, daemon=daemon)
    assert len(sent.named("DKIM2-Signature")) == 1
    assert sent.value("From") == f"Alice <{WRAPPED}>"


# --- sign mode ----------------------------------------------------------------------

def test_sign_mode_signs_each_copy_for_its_one_recipient(split, keys):
    first = fanout(split, keys)
    for rcpt in (SUBSCRIBER, OTHER):
        copy = resend(split, first, rcpt)
        assert copy.result == split.Milter.ACCEPT
        assert rt(copy) == [f"<{rcpt}>"]
        assert [copy.tag("DKIM2-Signature", "i"), copy.tag("DKIM2-Signature", "m")] == ["2", "3"]
        assert copy.tag("DKIM2-Signature", "f") == "exploded"
        assert copy.tag("DKIM2-Signature", "d") == "ietf.org"
        result = verified(split, copy)
        assert result.status == "pass", result.message


def test_sign_mode_removes_the_exploded_mark(split, keys):
    copy = resend(split, fanout(split, keys), SUBSCRIBER)
    assert copy.named("X-DKIM2-Exploded") == []


def test_sign_mode_changes_nothing_but_adds_the_signature(split, keys):
    first = fanout(split, keys)
    copy = resend(split, first, SUBSCRIBER)
    kinds = {a[0] for a in copy.actions}
    assert kinds <= {"addheader", "chgheader"}
    assert [a[1] for a in copy.actions if a[0] == "addheader"] == ["DKIM2-Signature"]
    assert [a[1:] for a in copy.actions if a[0] == "chgheader"] == [("X-DKIM2-Exploded", 1, None)]
    assert copy.named("Authentication-Results") == []


def test_sign_mode_without_the_mark_is_not_exploded(split, keys, monkeypatch):
    """An alias forward: pass 1 wraps From and records it; the expanded
    off-site copy is signed on pass 2 (queue id CCF1251 on rpi)."""
    alias = "chair@ietf.org"
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(split, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    monkeypatch.setattr(split, "get_db_pool", lambda: harness.FakeDB(virtual=[alias], down=False))
    split._policy_cache.clear()
    keydir, dns = keys
    plain = fields(("From", f"Alice <{AUTHOR}>"), ("To", alias), ("Subject", "hello"))
    made = dkim2hop.sign(dkim2hop.stream(plain, BODY, dns=dns, arriving=False), plain,
                         AUTHOR, [alias], keydir, timestamp=T)
    first = send(split, fields(*made.insert) + plain, BODY, AUTHOR, [alias], daemon="mx.ietf.org")
    assert first.value("X-DKIM2-Arrival") == "pass"
    assert first.value("From") == f"Alice <{WRAPPED}>"
    assert len(first.named("DKIM2-Signature")) == 1
    copy = resend(split, first, SUBSCRIBER)
    assert copy.tag("DKIM2-Signature", "f") is None
    assert rt(copy) == [f"<{SUBSCRIBER}>"]
    assert base64.b64decode(copy.tag("DKIM2-Signature", "mf")).decode() == f"<{first.mail_from}>"
    result = verified(split, copy)
    assert result.status == "pass", result.message


@pytest.mark.parametrize("status", ["fail", "permerror", "temperror"])
def test_sign_mode_does_not_sign_over_a_failed_arrival(split, keys, status):
    arrived = fields(("X-DKIM2-Arrival", status)) + author_post(keys)
    out, body = through_mailman(arrived)
    copy = send(split, out, body, BOUNCES, [SUBSCRIBER], daemon=SIGN)
    assert copy.result == split.Milter.ACCEPT
    assert len(copy.named("DKIM2-Signature")) == 1


def test_sign_mode_never_rewrites_or_touches_the_database(split, monkeypatch):
    """A DMARC-reject From that pass 1 would have wrapped: pass 2 leaves it,
    asks no DNS and no database, and so has nothing of ours to sign."""
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    dns = harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True))
    monkeypatch.setattr(split, "checkdmarc", dns)
    monkeypatch.setattr(split, "get_db_pool", lambda: harness.FakeDB(virtual=(), down=True))
    split._policy_cache.clear()
    copy = send(split, fields(*UNSIGNED), BODY + FOOTER, BOUNCES, [SUBSCRIBER], daemon=SIGN)
    assert copy.result == split.Milter.ACCEPT
    assert copy.value("From") == f"Alice <{AUTHOR}>"
    assert copy.mail_from == BOUNCES
    assert copy.named("DKIM2-Signature") == []
    assert not [a for a in copy.actions if a[0] in ("chgfrom", "addrcpt", "delrcpt")]


def test_sign_mode_starts_a_chain_on_our_own_unsigned_mail(split):
    plain = fields(("From", "chair@ietf.org"), ("To", SUBSCRIBER), ("Subject", "x"))
    copy = send(split, plain, BODY, "chair@ietf.org", [SUBSCRIBER], daemon=SIGN)
    assert [copy.tag("DKIM2-Signature", "i"), copy.tag("DKIM2-Signature", "m")] == ["1", "1"]
    result = verified(split, copy)
    assert result.status == "pass", result.message


def test_an_error_in_sign_mode_sends_the_copy_unsigned(split, keys, monkeypatch):
    first = fanout(split, keys)

    def boom(*a, **kw):
        raise RuntimeError("boom")
    monkeypatch.setattr(dkim2hop, "sign", boom)
    copy = resend(split, first, SUBSCRIBER)
    assert copy.result == split.Milter.ACCEPT
    assert len(copy.named("DKIM2-Signature")) == 1


# --- unset: today's behaviour ---------------------------------------------------------

def test_unset_signs_inline_whatever_the_daemon_name(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER, OTHER], auth=MAILMAN, daemon=SIGN)
    assert len(sent.named("DKIM2-Signature")) == 2
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert sent.named("X-DKIM2-Exploded") == []
