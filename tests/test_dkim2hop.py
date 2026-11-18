"""dkim2hop: verifying a DKIM2 chain on the way in, and adding the
rewriter's Message-Instance and DKIM2-Signature on the way out."""
import base64
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import dkim2hop  # noqa: E402

T = 1740000000   # a fixed timestamp; the verifier's age check is not under test
LIST = "ietf@ietf.org"
BOUNCES = "ietf-bounces@ietf.org"
BODY = b"Hello.\r\n\r\n-- \r\nlist footer\r\n"


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    """A key directory with ed25519 keys for example.com and ietf.org, and
    the DNS data that publishes them."""
    keydir = tmp_path_factory.mktemp("keys")
    dns = {}
    for domain in ("example.com", "ietf.org"):
        key = ed25519.Ed25519PrivateKey.generate()
        os.makedirs(keydir / domain)
        (keydir / domain / "sel1.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        dns[domain] = {"sel1._domainkey": [["txt", f"v=DKIM1; k=ed25519; p={public}"]]}
    return str(keydir), dns


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    # the verifier refuses signatures more than 14 days old
    import time
    monkeypatch.setattr(time, "time", lambda: T + 60)


def fields(*pairs):
    return [dkim2hop.header_field(n, v) for n, v in pairs]


def apply(signed, header_fields):
    """A message's header fields after the milter has done what sign() says."""
    return fields(*signed.insert) + list(header_fields)


def tag(field, name):
    import re
    value = b"".join(field.split(b":", 1)[1].split()).decode()
    m = re.search(rf"(?:^|;){name}=([^;]*)", value)
    return m.group(1) if m else None


def named(header_fields, name):
    return [f for f in header_fields if dkim2hop._name(f) == name]


def post(keys, sender="alice@example.com"):
    """A post to the list as its author's server sent it: signed i=1 by
    example.com, addressed to the list."""
    keydir, dns = keys
    before = fields(("From", f"Alice <{sender}>"), ("To", LIST), ("Subject", "hello"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, sender, [LIST], keydir, timestamp=T)
    assert signed, signed.reason
    return apply(signed, before)


# --- keys -------------------------------------------------------------------

def test_find_key_nearest_parent(keys):
    keydir, _dns = keys
    assert dkim2hop.find_key(keydir, "ietf.org")[:2] == ("ietf.org", "sel1")
    assert dkim2hop.find_key(keydir, "dmarc.ietf.org")[:2] == ("ietf.org", "sel1")
    assert dkim2hop.find_key(keydir, "DMARC.IETF.ORG.")[0] == "ietf.org"
    assert dkim2hop.find_key(keydir, "elsewhere.test") is None
    assert dkim2hop.find_key(keydir, "org") is None
    assert dkim2hop.find_key(keydir, "") is None


# --- a first signature --------------------------------------------------------

def test_unsigned_message_gets_m1_and_i1(keys):
    keydir, dns = keys
    before = fields(("From", "Chair <chair@ietf.org>"), ("To", "bob@example.net"), ("Subject", "x"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, "chair@ietf.org", ["bob@example.net"],
                           keydir, timestamp=T)
    assert [n for n, _v in signed.insert] == ["DKIM2-Signature", "Message-Instance"]
    assert signed.domain == "ietf.org"
    sent = apply(signed, before)
    sig = named(sent, b"dkim2-signature")[0]
    assert (tag(sig, "i"), tag(sig, "m"), tag(sig, "d")) == ("1", "1", "ietf.org")
    assert base64.b64decode(tag(sig, "mf")) == b"<chair@ietf.org>"
    assert base64.b64decode(tag(sig, "rt")) == b"<bob@example.net>"
    result = dkim2hop.verify(sent, BODY, "chair@ietf.org", ["bob@example.net"], dns)
    assert result.status == "pass", result.message


def test_inserted_fields_are_folded_for_a_milter(keys):
    keydir, dns = keys
    before = fields(("From", "chair@ietf.org"), ("To", "bob@example.net"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, "chair@ietf.org", ["bob@example.net"],
                           keydir, timestamp=T)
    for _name, value in signed.insert:
        assert "\r" not in value
        assert all(len(line) <= 110 for line in value.split("\n"))
        assert all(line.startswith("\t") for line in value.split("\n")[1:])


# --- continuing a chain, with the rewriter's own change --------------------------

def test_from_rewrite_is_recorded_and_signed(keys):
    keydir, dns = keys
    arrived = post(keys)
    assert dkim2hop.verify(arrived, BODY, "alice@example.com", [LIST], dns).status == "pass"

    wrapped = "alice=40example.com@dmarc.ietf.org"
    sending = [dkim2hop.header_field("From", f"Alice <{wrapped}>")
               if dkim2hop._name(f) == b"from" else f for f in arrived]
    signed = dkim2hop.sign(dkim2hop.stream(arrived, BODY, dns=dns, arriving=False),
                           sending, BOUNCES, ["sub@example.net"],
                           keydir, exploded=True, timestamp=T)
    assert signed, signed.reason
    assert [n for n, _v in signed.insert] == ["DKIM2-Signature", "Message-Instance"]
    sent = apply(signed, sending)

    top_mi = named(sent, b"message-instance")[0]
    assert tag(top_mi, "m") == "2"
    recipe = json.loads(base64.b64decode(tag(top_mi, "r")))
    # the old From, as it was after the colon (white space there is not hashed)
    assert list(recipe) == ["h"] and list(recipe["h"]) == ["from"]
    assert [s.strip() for s in recipe["h"]["from"][0]["d"]] == ["Alice <alice@example.com>"]

    top_sig = named(sent, b"dkim2-signature")[0]
    assert (tag(top_sig, "i"), tag(top_sig, "m"), tag(top_sig, "d")) == ("2", "2", "ietf.org")
    assert tag(top_sig, "f") == "exploded"
    assert base64.b64decode(tag(top_sig, "mf")) == f"<{BOUNCES}>".encode()

    result = dkim2hop.verify(sent, BODY, BOUNCES, ["sub@example.net"], dns)
    assert result.status == "pass", result.message


def test_unchanged_message_is_signed_over_the_instance_it_has(keys):
    keydir, dns = keys
    arrived = post(keys)
    signed = dkim2hop.sign(dkim2hop.stream(arrived, BODY, dns=dns, arriving=False),
                           arrived, BOUNCES, ["sub@example.net"],
                           keydir, timestamp=T)
    assert [n for n, _v in signed.insert] == ["DKIM2-Signature"]
    sent = apply(signed, arrived)
    assert tag(named(sent, b"dkim2-signature")[0], "m") == "1"
    assert dkim2hop.verify(sent, BODY, BOUNCES, ["sub@example.net"], dns).status == "pass"


def test_unsigned_instances_are_kept_and_signed_over(keys):
    """A post nobody signed, with our list manager's unsigned m=1: it came
    to us by a path we trust, so its instance stays, ours is the next one
    (with a Recipe back to it), and the one signature covers both."""
    keydir, dns = keys
    before = fields(("From", "Alice <alice@example.com>"), ("To", LIST))
    theirs = dkim2hop.dkim2sign.build_message_instance(dkim2hop._bare(before), BODY).encode() + b"\r\n"
    before = [theirs] + before
    after = [dkim2hop.header_field("From", "Alice <alice=40example.com@dmarc.ietf.org>")
             if dkim2hop._name(f) == b"from" else f for f in before]
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False), after, BOUNCES, ["sub@example.net"],
                           keydir, timestamp=T)
    assert signed, signed.reason
    assert [n for n, _v in signed.insert] == ["DKIM2-Signature", "Message-Instance"]
    sent = apply(signed, after)
    assert [tag(f, "m") for f in named(sent, b"message-instance")] == ["2", "1"]
    assert theirs in sent
    recipe = json.loads(base64.b64decode(tag(named(sent, b"message-instance")[0], "r")))
    assert [s.strip() for s in recipe["h"]["from"][0]["d"]] == ["Alice <alice@example.com>"]
    top_sig = named(sent, b"dkim2-signature")[0]
    assert (tag(top_sig, "i"), tag(top_sig, "m")) == ("1", "2")
    result = dkim2hop.verify(sent, BODY, BOUNCES, ["sub@example.net"], dns)
    assert result.status == "pass", result.message


def test_unsigned_instance_that_is_not_this_message_is_refused(keys):
    keydir, dns = keys
    before = fields(("From", "Chair <chair@ietf.org>"), ("To", LIST))
    wrong = dkim2hop.dkim2sign.build_message_instance(
        dkim2hop._bare(before), BODY + b"something else\r\n").encode() + b"\r\n"
    before = [wrong] + before
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False), before, BOUNCES, ["sub@example.net"],
                           keydir, timestamp=T)
    assert not signed and signed.reason.startswith("not signing")


# --- recording a change we do not sign for -----------------------------------------

def test_change_we_do_not_sign_is_recorded_in_an_unsigned_instance(keys):
    """The rewriter changed a hashed header field of a signed message and
    will not sign (no key for the sender): the chain still gets the next
    instance, so whoever of ours signs later can cover it."""
    keydir, dns = keys
    arrived = post(keys)
    after = [dkim2hop.header_field("To", "someone@example.net") if dkim2hop._name(f) == b"to" else f
             for f in arrived]
    recorded = dkim2hop.record(dkim2hop.stream(arrived, BODY, "alice@example.com", [LIST], dns), after)
    assert recorded, recorded.reason
    assert [n for n, _v in recorded.insert] == ["Message-Instance"]
    sent = apply(recorded, after)
    assert [tag(f, "m") for f in named(sent, b"message-instance")] == ["2", "1"]
    recipe = json.loads(base64.b64decode(tag(named(sent, b"message-instance")[0], "r")))
    assert list(recipe) == ["h"] and list(recipe["h"]) == ["to"]
    # as the next of our hops sees it: a chain that verifies, with one
    # instance nobody has signed yet
    assert dkim2hop.stream(sent, BODY, dns=dns, arriving=False).result().status == "pass"
    # and that hop signs over it
    signed = dkim2hop.sign(dkim2hop.stream(sent, BODY, dns=dns, arriving=False), sent, BOUNCES,
                           ["sub@example.net"], keydir, exploded=True, timestamp=T)
    assert signed, signed.reason
    final = apply(signed, sent)
    assert (tag(named(final, b"dkim2-signature")[0], "i"), tag(named(final, b"dkim2-signature")[0], "m")) == ("2", "2")
    assert dkim2hop.verify(final, BODY, BOUNCES, ["sub@example.net"], dns).status == "pass"


def test_change_to_a_message_with_no_chain_is_recorded_in_m1(keys):
    """The message enters DKIM2 here: one m=1 for the message as we send
    it, whose Recipe gives back the message as it was handed to us
    (-09 section 12.1: the first instance MAY carry Recipes)."""
    _keydir, dns = keys
    plain = fields(("From", "a@example.com"), ("To", LIST))
    changed = fields(("From", "a@example.com"), ("To", "someone@example.net"))
    recorded = dkim2hop.record(dkim2hop.stream(plain, BODY, "a@example.com", [LIST], dns), changed)
    assert [n for n, _v in recorded.insert] == ["Message-Instance"]
    sent = apply(recorded, changed)
    assert [tag(f, "m") for f in named(sent, b"message-instance")] == ["1"]
    recipe = json.loads(base64.b64decode(tag(named(sent, b"message-instance")[0], "r")))
    assert list(recipe) == ["h"] and [s.strip() for s in recipe["h"]["to"][0]["d"]] == [LIST]
    assert dkim2hop.stream(sent, BODY, dns=dns, arriving=False).result().status == "pass"


def test_first_signature_over_a_change_is_i1_m1(keys):
    """A message with no chain whose From we take over (an alias forward):
    one instance and one signature, i=1; m=1."""
    keydir, dns = keys
    before = fields(("From", "Alice <alice@example.com>"), ("To", LIST))
    after = [dkim2hop.header_field("From", "Alice <alice=40example.com@dmarc.ietf.org>")
             if dkim2hop._name(f) == b"from" else f for f in before]
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False), after,
                           "forwardingalgorithm@ietf.org", ["sub@example.net"], keydir, timestamp=T)
    assert signed, signed.reason
    assert [n for n, _v in signed.insert] == ["DKIM2-Signature", "Message-Instance"]
    sent = apply(signed, after)
    assert [tag(f, "m") for f in named(sent, b"message-instance")] == ["1"]
    top_sig = named(sent, b"dkim2-signature")[0]
    assert (tag(top_sig, "i"), tag(top_sig, "m")) == ("1", "1")
    recipe = json.loads(base64.b64decode(tag(named(sent, b"message-instance")[0], "r")))
    assert [s.strip() for s in recipe["h"]["from"][0]["d"]] == ["Alice <alice@example.com>"]
    result = dkim2hop.verify(sent, BODY, "forwardingalgorithm@ietf.org", ["sub@example.net"], dns)
    assert result.status == "pass", result.message


def test_change_to_a_chain_that_failed_is_still_recorded(keys):
    _keydir, dns = keys
    arrived = post(keys)
    broken = dkim2hop.stream(arrived, BODY + b"more\r\n", "alice@example.com", [LIST], dns)
    assert broken.result().status == "fail"
    after = [dkim2hop.header_field("To", "someone@example.net") if dkim2hop._name(f) == b"to" else f
             for f in arrived]
    recorded = dkim2hop.record(broken, after)
    assert [tag(dkim2hop.header_field(n, v), "m") for n, v in recorded.insert] == ["2"]


def test_nothing_is_recorded_without_a_change_or_a_body_hash(keys):
    _keydir, dns = keys
    arrived = post(keys)
    # only fields DKIM2 does not hash were touched
    seen = dkim2hop.stream(arrived, BODY, "alice@example.com", [LIST], dns)
    assert dkim2hop.record(seen, arrived + fields(("X-Spam", "no"))).reason == "no hashed header field changed"
    # the body went by unhashed: there is nothing to put in h=
    plain = fields(("From", "a@example.com"), ("To", LIST))
    changed = fields(("From", "a@example.com"), ("To", "someone@example.net"))
    unhashed = dkim2hop.stream(plain, BODY, "a@example.com", [LIST], dns, may_sign=False)
    assert dkim2hop.record(unhashed, changed).reason == "the body was not hashed"


# --- refusals ---------------------------------------------------------------------

def test_no_key_no_signature(keys):
    keydir, dns = keys
    before = fields(("From", "a@elsewhere.test"), ("To", "b@example.net"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, "a@elsewhere.test", ["b@example.net"], keydir)
    assert not signed and signed.reason == "no signing key for elsewhere.test"


def test_null_sender_is_not_signed(keys):
    keydir, dns = keys
    before = fields(("From", "MAILER-DAEMON@ietf.org"), ("To", "b@example.net"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, "<>", ["b@example.net"], keydir)
    assert not signed and "null" in signed.reason


def test_from_outside_the_signing_domain_is_refused(keys):
    keydir, dns = keys
    before = fields(("From", "Alice <alice@example.com>"), ("To", "b@example.net"))
    signed = dkim2hop.sign(dkim2hop.stream(before, BODY, dns=dns, arriving=False),
                           before, BOUNCES, ["b@example.net"], keydir, timestamp=T)
    assert not signed
    assert "From header field is not Authentic for d=ietf.org" in signed.reason


def test_broken_chain_is_not_extended(keys):
    keydir, dns = keys
    arrived = post(keys)
    tampered = [dkim2hop.header_field("Subject", "something else")
                if dkim2hop._name(f) == b"subject" else f for f in arrived]
    signed = dkim2hop.sign(dkim2hop.stream(tampered, BODY, dns=dns, arriving=False),
                           tampered, BOUNCES, ["sub@example.net"],
                           keydir, timestamp=T)
    assert not signed and signed.reason.startswith("not signing")


# --- verifying on the way in ------------------------------------------------------

def test_verify_none_pass_fail(keys):
    _keydir, dns = keys
    plain = fields(("From", "a@example.com"), ("To", LIST))
    assert dkim2hop.verify(plain, BODY, "a@example.com", [LIST], dns).status == "none"

    arrived = post(keys)
    assert dkim2hop.verify(arrived, BODY, "alice@example.com", [LIST], dns).status == "pass"
    assert dkim2hop.verify(arrived, BODY + b"more\r\n", "alice@example.com", [LIST], dns).status == "fail"
    # the same message replayed to someone the signer did not name
    assert dkim2hop.verify(arrived, BODY, "alice@example.com", ["other@ietf.org"], dns).status == "fail"


def test_authentication_results(keys):
    _keydir, dns = keys
    arrived = post(keys)
    ok = dkim2hop.verify(arrived, BODY, "alice@example.com", [LIST], dns)
    assert dkim2hop.authentication_results(ok, "mail.ietf.org").startswith("mail.ietf.org; dkim2=pass")
    bad = dkim2hop.verify(arrived, BODY + b"x\r\n", "alice@example.com", [LIST], dns)
    value = dkim2hop.authentication_results(bad, "mail.ietf.org")
    assert value.startswith('mail.ietf.org; dkim2=fail reason="')
    assert "\n" not in value


# --- the body is never held --------------------------------------------------------

def test_stream_keeps_no_body(keys):
    import tracemalloc
    keydir, dns = keys
    arrived = post(keys)
    piece = (b"x" * 70 + b"\r\n") * 900          # about 64 KB
    tracemalloc.start()
    seen = dkim2hop.Stream(arrived, "alice@example.com", [LIST], dns)
    for _ in range(100):                           # about 6.5 MB in all
        seen.feed(piece)
    seen.result()
    signed = dkim2hop.sign(seen, arrived, BOUNCES, ["sub@example.net"], keydir, timestamp=T)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 1_000_000, peak
    # (the body is not the one example.com signed, so this is refused: the
    # point is what it cost to find that out)
    assert not signed


def test_stream_in_pieces_is_the_whole(keys):
    _keydir, dns = keys
    arrived = post(keys)
    seen = dkim2hop.Stream(arrived, "alice@example.com", [LIST], dns)
    for i in range(0, len(BODY), 3):
        seen.feed(BODY[i:i + 3])
    assert seen.result().status == "pass"
    assert seen.body_hash() == dkim2hop.dkim2sign.compute_body_hash(BODY)
    assert not seen.changed_since_signature()
    more = dkim2hop.stream(arrived, BODY + b"footer\r\n", dns=dns, arriving=False)
    assert more.changed_since_signature()


def test_changed_since_signature(keys):
    """Mailman's rule (_dkim2_rewrites_from): a post nobody signed, or one
    whose hashed header fields or body changed since the newest signature."""
    _keydir, dns = keys
    arrived = post(keys)
    same = dkim2hop.stream(arrived, BODY, dns=dns, arriving=False)
    assert not same.changed_since_signature()
    footer = dkim2hop.stream(arrived, BODY + b"footer\r\n", dns=dns, arriving=False)
    assert footer.changed_since_signature()
    tagged = [dkim2hop.header_field("Subject", "[ietf] hello") if dkim2hop._name(f) == b"subject" else f
              for f in arrived]
    assert dkim2hop.stream(tagged, BODY, dns=dns, arriving=False).changed_since_signature()
    plain = fields(("From", "a@example.com"), ("To", LIST))
    assert dkim2hop.stream(plain, BODY, dns=dns, arriving=False).changed_since_signature()


def test_unhashed_body_is_not_signed(keys):
    keydir, dns = keys
    plain = fields(("From", "chair@ietf.org"), ("To", "bob@example.net"))
    seen = dkim2hop.stream(plain, BODY, dns=dns, arriving=False, may_sign=False)
    assert not seen.hashed and seen.body_hash() is None
    assert seen.result().status == "none"
    assert seen.changed_since_signature()
    signed = dkim2hop.sign(seen, plain, "chair@ietf.org", ["bob@example.net"], keydir, timestamp=T)
    assert not signed and signed.reason == "the body was not hashed"
