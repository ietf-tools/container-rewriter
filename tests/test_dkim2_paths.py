"""When the DMARC From rewrite (the DKIM1 "munge") is used.

A list copy that DKIM2 will answer for (mailman recorded its instance, we
hold a key, the arrival did not fail, the chain verifies) is on the DKIM2
path: the DMARC rule is not consulted, and the DKIM2 From rule alone
decides From.  Any other list copy is munged as before.  An alias forward
takes the DKIM2 path only with ALIAS_DKIM2 on, and only when our signature
can extend the sender's chain."""
import harness
from test_dkim2_milter import (AUTHOR, BODY, BOUNCES, FOOTER, LIST, MAILMAN, SUBSCRIBER,  # noqa: F401
                               UNSIGNED, WRAPPED, author_post, fields, send, through_mailman)


def pin_reject(rw, monkeypatch):
    fake = harness.FakeDNS(harness.parse_pins(["example.com=reject"], "--dmarc"), {}, True)
    monkeypatch.setattr(rw, "checkdmarc", harness.LoggedCheckdmarc(fake))
    rw._policy_cache.clear()
    return fake


def dmarc_lookups(fake):
    return [q[0] for q in fake.queries if q[0].startswith("_dmarc.")]


# --- list copies ------------------------------------------------------------------------

def test_list_copy_on_the_dkim2_path_makes_no_dmarc_lookup(dkim2, monkeypatch):
    fake = pin_reject(dkim2, monkeypatch)
    plain = fields(("X-DKIM2-Arrival", "none"), ("From", f"Alice <{AUTHOR}>"), ("To", LIST),
                   ("Subject", "hello"))
    out, body = through_mailman(plain)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"            # the DKIM2 rule
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["1", "1"]
    assert dmarc_lookups(fake) == []


def test_list_copy_without_an_instance_is_munged(dkim2, monkeypatch):
    pin_reject(dkim2, monkeypatch)
    sent = send(dkim2, fields(*UNSIGNED), BODY + FOOTER, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert sent.named("DKIM2-Signature") == []


def test_list_copy_with_a_failed_arrival_is_munged(dkim2, keys, monkeypatch):
    pin_reject(dkim2, monkeypatch)
    out, body = through_mailman(fields(("X-DKIM2-Arrival", "fail")) + author_post(keys))
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"


def test_list_copy_with_no_key_is_munged(dkim2, keys, monkeypatch, tmp_path):
    pin_reject(dkim2, monkeypatch)
    monkeypatch.setattr(dkim2, "dkim2_keydir", str(tmp_path))
    out, body = through_mailman(fields(("X-DKIM2-Arrival", "pass")) + author_post(keys))
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"


def test_signed_unchanged_list_copy_keeps_its_from(dkim2, keys, monkeypatch):
    pin_reject(dkim2, monkeypatch)
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    sent = send(dkim2, arrived, BODY, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{AUTHOR}>"


def test_the_munge_setting_is_gone(rewriter):
    assert not hasattr(rewriter, "dkim1_munge_from")


# --- aliases: ALIAS_DKIM2 ---------------------------------------------------------------

import dkim2hop  # noqa: E402
import pytest  # noqa: E402
from test_dkim2_milter import T, verified  # noqa: E402
from test_dkim2_split import resend  # noqa: E402,F401
from test_dkim2_split import send as send_split  # noqa: E402

ALIAS = "chair@ietf.org"
FORWARDING_ADDR = "forwardingalgorithm@dmarc.ietf.org"
ELSEWHERE = "someone@elsewhere.example"


def alias_post(keys, rcpt=ALIAS, sender=AUTHOR):
    """A post signed by its author's server (i=1) for one recipient."""
    keydir, dns = keys
    plain = fields(("From", f"Alice <{sender}>"), ("To", rcpt), ("Subject", "hello"))
    signed = dkim2hop.sign(dkim2hop.stream(plain, BODY, dns=dns, arriving=False), plain,
                           sender, [rcpt], keydir, timestamp=T)
    assert signed, signed.reason
    return fields(*signed.insert) + plain


def alias_setup(rw, monkeypatch, on, alias=ALIAS):
    fake = pin_reject(rw, monkeypatch)
    monkeypatch.setattr(rw, "alias_dkim2", on)
    db = harness.FakeDB(virtual=[alias], down=False)
    monkeypatch.setattr(rw, "get_db_pool", lambda: db)
    return fake, db


@pytest.mark.parametrize("value,expected", [
    (None, False), ("", False), ("no", False), ("yes", True), ("Yes ", True), ("1", True),
    ("on", True), ("TRUE", True)])
def test_alias_setting_is_parsed(rewriter, value, expected):
    assert rewriter.alias_dkim2_setting(value) is expected


def test_alias_flag_off_munges_as_before(split, keys, monkeypatch):
    _fake, db = alias_setup(split, monkeypatch, False)
    first = send_split(split, alias_post(keys), BODY, AUTHOR, [ALIAS], daemon="mx.ietf.org")
    assert first.value("From") == f"Alice <{WRAPPED}>"
    assert first.mail_from == FORWARDING_ADDR
    assert len(db.writes) == 1


def test_alias_flag_on_keeps_from_and_extends_the_chain(split, keys, monkeypatch):
    fake, db = alias_setup(split, monkeypatch, True)
    first = send_split(split, alias_post(keys), BODY, AUTHOR, [ALIAS], daemon="mx.ietf.org")
    assert first.value("X-DKIM2-Arrival") == "pass"
    assert first.value("From") == f"Alice <{AUTHOR}>"
    assert first.mail_from == FORWARDING_ADDR
    assert db.writes == []
    assert dmarc_lookups(fake) == []
    copy = resend(split, first, ELSEWHERE)
    assert [copy.tag("DKIM2-Signature", "i"), copy.tag("DKIM2-Signature", "d")] == ["2", "ietf.org"]
    result = verified(split, copy)
    assert result.status == "pass", result.message


def test_alias_flag_on_without_a_dkim2_chain_munges(split, monkeypatch):
    alias_setup(split, monkeypatch, True)
    plain = fields(("From", f"Alice <{AUTHOR}>"), ("To", ALIAS), ("Subject", "hello"))
    first = send_split(split, plain, BODY, AUTHOR, [ALIAS], daemon="mx.ietf.org")
    assert first.value("From") == f"Alice <{WRAPPED}>"


def test_alias_flag_on_with_a_domain_mismatch_munges(split, keys, monkeypatch):
    alias = "chair@lists.example"
    monkeypatch.setattr(split, "local_domains", "ietf.org lists.example")
    alias_setup(split, monkeypatch, True, alias=alias)
    first = send_split(split, alias_post(keys, rcpt=alias), BODY, AUTHOR, [alias], daemon="mx.ietf.org")
    assert first.value("X-DKIM2-Arrival") == "pass"
    assert first.value("From") == f"Alice <{WRAPPED}>"


def test_alias_flag_on_with_no_key_munges(split, keys, monkeypatch, tmp_path):
    alias_setup(split, monkeypatch, True)
    post = alias_post(keys)
    import shutil
    keydir, _dns = keys
    shutil.copytree(f"{keydir}/example.com", tmp_path / "example.com")   # not the forwarding domain's
    monkeypatch.setattr(split, "dkim2_keydir", str(tmp_path))
    first = send_split(split, post, BODY, AUTHOR, [ALIAS], daemon="mx.ietf.org")
    assert first.value("From") == f"Alice <{WRAPPED}>"


def null_sender_post(keys, rcpt=ALIAS):
    """A DSN-like message a remote DKIM2 server signed with mf=<>: our own
    signer refuses a null sender, so this is built with the vendored one."""
    keydir, dns = keys
    plain = fields(("From", f"Alice <{AUTHOR}>"), ("To", rcpt), ("Subject", "bounce"))
    seen = dkim2hop.stream(plain, BODY, dns=dns, arriving=False)
    added = dkim2hop.dkim2sign.sign_fields(
        dkim2hop._bare(plain), {"sha256": seen.body_hash("sha256")}, "sel1", "example.com",
        f"{keydir}/example.com/sel1.key", mailfrom="<>", rcptto=[f"<{rcpt}>"], timestamp=T,
        skip_upstream_check=True)
    return [f.encode() + b"\r\n" for f in added] + plain


def test_alias_flag_on_bounce_is_munged_and_keeps_a_null_sender(split, keys, monkeypatch):
    """A bounce can never be signed by us (sign() refuses a null sender), so
    it is no use keeping its From for a signature: the DMARC rule wraps it,
    and the envelope stays null."""
    alias_setup(split, monkeypatch, True)
    first = send_split(split, null_sender_post(keys), BODY, "", [ALIAS], daemon="mx.ietf.org")
    assert first.value("X-DKIM2-Arrival") == "pass"
    assert first.mail_from == ""
    assert first.value("From") == f"Alice <{WRAPPED}>"


def test_reply_to_a_wrap_takes_the_path_in_single_pass(dkim2, keys, monkeypatch):
    wrap = "alice=40example.org@dmarc.ietf.org"
    alias_setup(dkim2, monkeypatch, True, alias=wrap)
    post = alias_post(keys, rcpt=wrap, sender="bob@example.com")
    sent = send(dkim2, post, BODY, "bob@example.com", [wrap])
    assert sent.rcpts == ["alice@example.org"]
    assert sent.value("From") == "Alice <bob@example.com>"
    assert sent.mail_from == FORWARDING_ADDR
    assert sent.tag("DKIM2-Signature", "i") == "2"
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_can_extend_chain(keys):
    _keydir, dns = keys
    post = alias_post(keys)
    seen = dkim2hop.stream(post, BODY, dns=dns, arriving=False)
    assert dkim2hop.can_extend_chain(seen, FORWARDING_ADDR)
    assert not dkim2hop.can_extend_chain(seen, "x@dmarc.example.org")
    plain = fields(("From", f"Alice <{AUTHOR}>"), ("To", ALIAS))
    assert not dkim2hop.can_extend_chain(dkim2hop.stream(plain, BODY, dns=dns, arriving=False), FORWARDING_ADDR)
    keydir, _ = keys
    two = fields(("From", f"Alice <{AUTHOR}>"), ("To", ALIAS), ("Subject", "hello"))
    signed = dkim2hop.sign(dkim2hop.stream(two, BODY, dns=dns, arriving=False), two, AUTHOR,
                           ["a@x.example", ALIAS], keydir, timestamp=T)
    both = dkim2hop.stream(fields(*signed.insert) + two, BODY, dns=dns, arriving=False)
    assert dkim2hop.can_extend_chain(both, FORWARDING_ADDR)


# --- on the DKIM2 path means signed: the guards that keep a copy from going
# out neither wrapped nor signed ---------------------------------------------------------

def test_alias_flag_on_with_a_failed_arrival_munges(split, keys, monkeypatch):
    """rt= still names the alias, but the chain did not verify: nothing of
    ours will sign it."""
    alias_setup(split, monkeypatch, True)
    first = send_split(split, alias_post(keys), BODY + b"tampered\r\n", AUTHOR, [ALIAS],
                       daemon="mx.ietf.org")
    assert first.value("X-DKIM2-Arrival") == "fail"
    assert first.value("From") == f"Alice <{WRAPPED}>"


def test_alias_flag_on_in_a_single_pass_munges(dkim2, keys, monkeypatch):
    """Without split-then-sign the rewriter never sees the alias's off-site
    copy, so it cannot sign it: From is wrapped as before."""
    alias_setup(dkim2, monkeypatch, True)
    sent = send(dkim2, alias_post(keys), BODY, AUTHOR, [ALIAS])
    assert sent.value("X-DKIM2-Arrival") == "pass"
    assert sent.value("From") == f"Alice <{WRAPPED}>"


def test_list_copy_whose_chain_does_not_verify_is_munged(dkim2, keys, monkeypatch):
    """Mailman's instance is there, but the copy no longer matches it: the
    chain fails, nothing will sign, and the DMARC rule wraps From."""
    pin_reject(dkim2, monkeypatch)
    out, body = through_mailman(fields(("X-DKIM2-Arrival", "pass")) + author_post(keys))
    sent = send(dkim2, out, body + b"tampered\r\n", BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert len(sent.named("DKIM2-Signature")) == 1
