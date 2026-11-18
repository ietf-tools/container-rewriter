"""A list fan-out keeps one Message-Instance for the list.

Mailman hands each copy back with an unsigned Message-Instance saying what
the list changed.  The rewriter's own changes to that copy (the From it
takes over) are made by the same organisation in the same hop, so they go
into mailman's instance rather than a new one above it: the instance keeps
its m=, gets the hashes of the copy as it leaves, and one Recipe back to
the message as the list received it.  Mail that is not a list's fan-out,
or a list instance someone has already signed, still gets an instance of
its own."""
import base64

import dkim2hop
import harness
from test_dkim2_milter import (AUTHOR, BODY, BOUNCES, LIST, MAILMAN, SUBSCRIBER,  # noqa: F401
                               WRAPPED, author_post, dkim2, fields, keys, send,
                               through_mailman, verified, versions)
from test_dkim2_split import SIGN, resend, split  # noqa: F401
from test_dkim2_split import send as send_split


def recipe(sent, m):
    """The decoded r= of the instance with m=<m>."""
    for f in sent.named("Message-Instance"):
        value = f.split(b":", 1)[1].decode()
        if dkim2hop.dkim2sign._extract_tag(value, "m") == str(m):
            return dkim2hop.dkim2undo.decode_recipes(value)
    raise AssertionError(f"no m={m}")


def before(sent, m):
    """The header fields as they were before the hop that wrote m=<m>."""
    bare = [f[:-2] for f in sent.fields]
    return dkim2hop.dkim2undo.reconstruct_headers(bare, recipe(sent, m)["h"])


def from_in(headers):
    return [h.split(b":", 1)[1].strip().decode() for h in headers
            if h.split(b":", 1)[0].strip().lower() == b"from"]


def test_footer_copy_leaves_with_one_instance_for_the_list(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert versions(sent) == ["2", "1"]
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["2", "2"]
    # mailman's field was rewritten in place, not added to
    assert not [a for a in sent.actions if a[0] == "addheader" and a[1] == "Message-Instance"]
    assert [a[1:3] for a in sent.actions if a[0] == "chgheader"
            and a[1] == "Message-Instance"] == [("Message-Instance", 1)]
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_the_list_instance_undoes_both_changes(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    prev = before(sent, 2)
    # the From the author sent, and the subject before the list's tag
    assert from_in(prev) == [f"Alice <{AUTHOR}>"]
    # (a field the Recipe rebuilds carries its lower-case name, -09 section 5)
    assert [h.split(b":", 1)[1].strip() for h in prev if h.lower().startswith(b"subject:")] == [b"hello"]
    assert not [h for h in prev if h.lower().startswith(b"list-id:")]
    # the body Recipe is mailman's, untouched
    assert "b" in recipe(sent, 2)


def test_unsigned_post_keeps_mailmans_m1(dkim2, monkeypatch):
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    dkim2._policy_cache.clear()
    plain = fields(("X-DKIM2-Arrival", "none"), ("From", f"Alice <{AUTHOR}>"), ("To", LIST),
                   ("Subject", "hello"))
    out, body = through_mailman(plain)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert versions(sent) == ["1"]
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["1", "1"]
    # mailman's m=1 had no Recipe; ours says how to get the From back
    assert from_in(before(sent, 1)) == [f"Alice <{AUTHOR}>"]
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_split_first_pass_rewrites_the_list_instance(split, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    first = send_split(split, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN, daemon="ORIGINATING")
    assert versions(first) == ["2", "1"]
    assert len(first.named("DKIM2-Signature")) == 1
    copy = resend(split, first, SUBSCRIBER)
    assert versions(copy) == ["2", "1"]
    assert [copy.tag("DKIM2-Signature", "i"), copy.tag("DKIM2-Signature", "m")] == ["2", "2"]
    result = verified(split, copy)
    assert result.status == "pass", result.message


def test_null_body_recipe_survives_the_merge(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived, null_body=True)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert versions(sent) == ["2", "1"]
    assert recipe(sent, 2)["b"] is None
    result = verified(dkim2, sent)
    assert result.status == "permerror" and "m=2 has a null recipe" in result.message


def test_a_signed_top_instance_is_not_rewritten(keys):
    # the post's own m=1 is covered by i=1: a change gets an m=2 of its own
    _keydir, dns = keys
    post = author_post(keys)
    seen = dkim2hop.stream(post, BODY, dns=dns, arriving=False)
    after = [dkim2hop.header_field("To", "someone@example.org") if dkim2hop._name(f) == b"to" else f
             for f in post]
    recorded = dkim2hop.record(seen, after, merge=True)
    assert not recorded.change
    assert [n for n, _v in recorded.insert] == ["Message-Instance"]
    assert "m=2" in recorded.insert[0][1]


def test_mail_that_is_not_a_fanout_keeps_its_own_instance(dkim2, keys):
    # the same list copy, but not handed to us by mailman
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth="someone@ietf.org")
    assert not [a for a in sent.actions if a[0] == "chgheader" and a[1] == "Message-Instance"]


def test_mf_names_the_envelope(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert base64.b64decode(sent.tag("DKIM2-Signature", "mf")).decode() == f"<{sent.mail_from}>"
