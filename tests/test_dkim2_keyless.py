"""No signing keys: no DKIM2 chain leaves with a change we cannot sign for.

A rewriter with no key directory cannot sign, so a chain it sends on (to
a new recipient, or with header fields it changed) will not verify at the
next hop: the top Message-Instance or signature does not match what
arrives (draft-ietf-dkim-dkim2-spec-09 sections 13.1, 14.2).  It removes
every DKIM2-Signature and Message-Instance field instead, which leaves
the message with no chain at all (status NONE), and it records nothing
in an unsigned instance of its own.  Mail delivered unchanged to a local
list keeps its chain for mailman."""
import logging

import pytest

import harness

from test_dkim2_milter import (AUTHOR, BODY, BOUNCES, LIST, MAILMAN, SUBSCRIBER,  # noqa: F401
                               UNWRAPPED, WRAP, author_post, dkim2, fields, keys,
                               through_mailman, to_list_and_wrap, versions)
from test_dkim2_split import SIGN, OTHER, send, split  # noqa: F401


@pytest.fixture
def keyless(dkim2, monkeypatch):
    monkeypatch.setattr(dkim2, "dkim2_keydir", "")
    monkeypatch.setattr(dkim2, "get_db_pool", lambda: harness.FakeDB(virtual=[WRAP], down=False))
    return dkim2


@pytest.fixture
def keyless_split(split, monkeypatch):
    monkeypatch.setattr(split, "dkim2_keydir", "")
    return split


def no_chain(sent):
    return sent.named("DKIM2-Signature") == [] and sent.named("Message-Instance") == []


def test_a_signed_post_sent_off_site_leaves_with_no_chain(keyless, keys, caplog):
    caplog.set_level(logging.INFO, logger="rewriter")
    sent = send(keyless, to_list_and_wrap(keys), BODY, AUTHOR, [LIST, WRAP])
    assert sent.result == keyless.Milter.ACCEPT
    assert sent.value("To") == f"{LIST}, {UNWRAPPED}"
    assert no_chain(sent)
    assert "dkim2: no signing keys, removed 2 DKIM2 header fields" in caplog.text


def test_an_unsigned_change_is_not_recorded(keyless, keys):
    sent = send(keyless, to_list_and_wrap(keys, signed=False), BODY, AUTHOR, [LIST, WRAP])
    assert sent.value("To") == f"{LIST}, {UNWRAPPED}"
    assert no_chain(sent)


def test_a_post_for_the_list_alone_keeps_its_chain(keyless, keys):
    sent = send(keyless, author_post(keys), BODY, AUTHOR, [LIST], daemon="mx.ietf.org")
    assert len(sent.named("DKIM2-Signature")) == 1
    assert versions(sent) == ["1"]
    assert not [a for a in sent.actions if a[0] == "chgheader" and a[1] in
                ("DKIM2-Signature", "Message-Instance")]


def test_the_list_fanout_leaves_with_no_chain(keyless_split, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(keyless_split, out, body, BOUNCES, [SUBSCRIBER, OTHER], auth=MAILMAN,
                daemon="ORIGINATING")
    assert no_chain(sent)


def test_the_signing_pass_removes_mailmans_unsigned_chain(keyless_split, keys, monkeypatch):
    monkeypatch.setattr(keyless_split, "list_verp", True)
    out, body = through_mailman(fields(("From", f"Alice <{AUTHOR}>"), ("To", LIST),
                                       ("Subject", "hello"), ("X-DKIM2-Exploded", "yes")))
    assert versions(_as_sent(out)) == ["1"]
    copy = send(keyless_split, out, body, BOUNCES, [SUBSCRIBER], daemon=SIGN)
    assert copy.result == keyless_split.Milter.ACCEPT
    assert no_chain(copy)
    assert copy.named("X-DKIM2-Exploded") == []
    # VERP does not need keys
    assert copy.mail_from == "ietf-bounces+sub=example.net@ietf.org"


def _as_sent(header_fields):
    from test_dkim2_milter import Sent
    return Sent(None, [], header_fields, b"", "", [])
