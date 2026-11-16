"""VERP for list copies, and bounces that come back to it.

With LIST_VERP on, the signing pass gives each list copy (one recipient by
then) an envelope sender in mailman's VERP format, so a bounce names the
subscriber.  A bounce to an address we wrapped has the wrap undone in To:
and Cc: as well as in the envelope: mailman reads the VERP address from
To:."""
import base64
import re

import pytest

from test_dkim2_split import (BODY, BOUNCES, LIST, MAILMAN, SIGN, SUBSCRIBER,  # noqa: F401
                              dkim2, fields, keys, resend, send, split, verified)

# mailman's default verp_regexp (src/mailman/config/schema.cfg)
MAILMAN_VERP = re.compile(r"^(?P<bounces>[^+]+?)\+(?P<local>[^=]+)=(?P<domain>[^@]+)@.*$", re.I)


@pytest.fixture
def verp(split, monkeypatch):
    monkeypatch.setattr(split, "list_verp", True)
    return split


def list_copy(rewriter, mail_from=BOUNCES, rcpt=SUBSCRIBER):
    """A list's own mail, as pass 1 hands it to the signing pass."""
    own = fields(("From", "ietf-owner@ietf.org"), ("To", rcpt), ("Subject", "notice"),
                 ("X-DKIM2-Exploded", "yes"))
    return send(rewriter, own, BODY, mail_from, [rcpt], daemon=SIGN)


def test_list_copy_gets_mailmans_verp_sender(verp):
    copy = list_copy(verp)
    assert copy.mail_from == "ietf-bounces+sub=example.net@ietf.org"
    m = MAILMAN_VERP.match(copy.mail_from)
    assert (m["bounces"], m["local"], m["domain"]) == ("ietf-bounces", "sub", "example.net")


def test_the_signature_names_the_verp_sender(verp):
    copy = list_copy(verp)
    assert base64.b64decode(copy.tag("DKIM2-Signature", "mf")).decode() == f"<{copy.mail_from}>"
    result = verified(verp, copy)
    assert result.status == "pass", result.message


def test_a_wrapped_list_sender_keeps_its_wrap(verp):
    copy = list_copy(verp, mail_from="ietf-bounces=40ietf.org@dmarc.ietf.org")
    assert copy.mail_from == "ietf-bounces+sub=example.net=40ietf.org@dmarc.ietf.org"
    assert verp.unwrap_addr(copy.mail_from) == "ietf-bounces+sub=example.net@ietf.org"


def test_off_by_default(split):
    copy = list_copy(split)
    assert copy.mail_from == BOUNCES
    assert not [a for a in copy.actions if a[0] == "chgfrom"]


@pytest.mark.parametrize("mail_from", [
    "forwardingalgorithm@dmarc.ietf.org",       # an alias forward
    "chair@ietf.org",                           # our own mail
    "ietf-bounces+sub=example.net@ietf.org",    # mailman already did it
    "ietf-bounces+probe-token@ietf.org",        # a mailman probe
])
def test_only_a_plain_list_bounce_sender_is_changed(verp, mail_from):
    copy = list_copy(verp, mail_from=mail_from)
    assert copy.mail_from == mail_from


@pytest.mark.parametrize("mail_from", [
    "golang-nuts-bounces@googlegroups.com",            # someone else's list, forwarded
    "announce-bounces@lists.example.org",
    "ietf-bounces=40googlegroups.com@dmarc.ietf.org",  # our wrap, not our list
    "ietf-bounces=40ietf.org@dmarc.example.org",       # not our wrap
])
def test_another_organisations_list_sender_is_left_alone(verp, mail_from):
    copy = list_copy(verp, mail_from=mail_from)
    assert copy.mail_from == mail_from


@pytest.mark.parametrize("rcpt", ['"odd user"@example.net', "a=b@example.net", "user@exämple.net"])
def test_a_recipient_mailman_could_not_parse_back_is_left_alone(verp, rcpt):
    copy = list_copy(verp, rcpt=rcpt)
    assert copy.mail_from == BOUNCES


def test_without_signing_keys_the_copy_still_gets_verp(verp, monkeypatch):
    monkeypatch.setattr(verp, "dkim2_keydir", "")
    copy = list_copy(verp)
    assert copy.mail_from == "ietf-bounces+sub=example.net@ietf.org"
    assert copy.named("DKIM2-Signature") == []


# --- the bounce coming back ------------------------------------------------------------

WRAPPED_VERP = "ietf-bounces+sub=example.net=40ietf.org@dmarc.ietf.org"


def test_a_bounce_to_a_wrapped_verp_address_reaches_mailman_readable(dkim2):
    dsn = fields(("From", "MAILER-DAEMON@example.net"), ("To", WRAPPED_VERP),
                 ("Subject", "Undelivered Mail Returned to Sender"))
    back = send(dkim2, dsn, BODY, "", [WRAPPED_VERP], daemon="mx.ietf.org")
    assert back.rcpts == ["ietf-bounces+sub=example.net@ietf.org"]
    assert back.value("To") == "ietf-bounces+sub=example.net@ietf.org"
    m = MAILMAN_VERP.match(back.value("To"))
    assert f"{m['local']}@{m['domain']}" == "sub@example.net"


def test_other_addresses_in_the_bounce_headers_are_kept(dkim2):
    dsn = fields(("From", "MAILER-DAEMON@example.net"),
                 ("To", f"Someone <someone@example.org>, {WRAPPED_VERP}"), ("Subject", "x"))
    back = send(dkim2, dsn, BODY, "", [WRAPPED_VERP], daemon="mx.ietf.org")
    assert back.value("To") == "Someone <someone@example.org>, ietf-bounces+sub=example.net@ietf.org"


def test_a_bounce_already_unwrapped_has_its_headers_left_alone(dkim2):
    plain = "ietf-bounces+sub=example.net@ietf.org"
    dsn = fields(("From", "MAILER-DAEMON@example.net"), ("To", plain), ("Subject", "x"))
    back = send(dkim2, dsn, BODY, "", [plain], daemon="mx.ietf.org")
    assert not [a for a in back.actions if a[0] == "chgheader" and a[1] == "To"]
