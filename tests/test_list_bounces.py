"""Mailman 3 bounce addresses.

Mailman 3 sends list mail from <list>-bounces@<domain>, or with VERP from
<list>-bounces+<user>=<domain>@<domain>, and sends probes from
<list>-bounces+<token>@<domain>.  On a fan-out the milter may wrap that
envelope sender (<...>=40<domain>@<rewrite domain>); a bounce coming back to
it must be unwrapped by unwrap_list_bounces(), without the database check
used for replies to wrapped senders.
"""
import pytest

FWD = "dmarc.ietf.org"
MAILMAN_SENDERS = [
    pytest.param("ietf-bounces@ietf.org", id="plain"),
    pytest.param("ietf-bounces+alice=example.com@ietf.org", id="verp"),
    pytest.param("ietf-bounces+alice.smith=mail.example.co.uk@ietf.org", id="verp-subdomain"),
    pytest.param("ietf-bounces+8f3a9c2e1d6b4a70@ietf.org", id="probe"),
    pytest.param("test.list_2-bounces@ietf.org", id="list-name-punctuation"),
    pytest.param("IETF-Bounces@IETF.org", id="mixed-case"),
]


def reply_lookups(report):
    # the lookup scenario 1 makes before unwrapping a reply
    return [q for q in report["db_queries"] if "email = %s" in q]


@pytest.mark.parametrize("addr", [
    "ietf-bounces@ietf.org",
    "ietf-bounces+alice=example.com@ietf.org",
    "ietf-bounces+8f3a9c2e1d@ietf.org",
    "a-b.c_d-bounces@ietf.org",
    "IETF-BOUNCES@ietf.org",
    f"ietf-bounces=40ietf.org@{FWD}",
    f"ietf-bounces+alice=example.com=40ietf.org@{FWD}",
    f"ietf-bounces+8f3a9c2e1d=40ietf.org@{FWD}",
    "bounces-bounces@ietf.org",
])
def test_listbounce_regex_matches(rewriter, addr):
    assert rewriter.listbounce_mailmatch.search(addr)


@pytest.mark.parametrize("addr", [
    pytest.param("ietf@ietf.org", id="posting-address"),
    pytest.param("ietf-request@ietf.org", id="request"),
    pytest.param("ietf-owner@ietf.org", id="owner"),
    pytest.param("ietf-bounce@ietf.org", id="bounce-singular"),
    pytest.param("ietf-bouncesfoo@ietf.org", id="suffix-after-bounces"),
    pytest.param("ietf-bouncess@ietf.org", id="extra-s"),
    pytest.param("-bounces@ietf.org", id="empty-list-name"),
    pytest.param("ietf+x-bounces@ietf.org", id="plus-before-bounces"),
    pytest.param("ietf-bounces=41ietf.org@ietf.org", id="not-a-wrap"),
    pytest.param("alice@ietf-bounces.org", id="bounces-in-domain"),
    pytest.param(f"alice=40example.com@{FWD}", id="wrapped-sender"),
])
def test_listbounce_regex_rejects(rewriter, addr):
    assert not rewriter.listbounce_mailmatch.search(addr)


@pytest.mark.parametrize("env_from", MAILMAN_SENDERS)
def test_fanout_detected(run, env_from):
    # a virtual alias among the subscribers would switch a single message
    # to FORWARDING_ADDR; a fan-out keeps the list's own (wrapped) sender
    report = run("--list", "ietf@ietf.org", "-f", env_from,
                 "--from", "alice@example.com", "--dmarc", "example.com=reject",
                 "--to", "a@x.test", "alias@ietf.org", "--virtual", "alias@ietf.org")
    local = env_from.rpartition("@")[0]
    assert report["envelope_from"] == f"{local}=40ietf.org@{FWD}"


@pytest.mark.parametrize("env_from", MAILMAN_SENDERS)
def test_bounce_round_trip(run, env_from):
    """Wrap a fan-out's sender, then bounce a message back to it."""
    out = run("--list", "ietf@ietf.org", "-f", env_from,
              "--from", "alice@example.com", "--dmarc", "example.com=reject",
              "--to", "a@x.test")
    wrapped = out["envelope_from"]
    assert wrapped.endswith(f"=40ietf.org@{FWD}")

    back = run("--from", "MAILER-DAEMON@x.test", "-f", "", "--to", wrapped)
    local = env_from.rpartition("@")[0]
    assert back["recipients"] == [f"{local}@ietf.org"]
    assert reply_lookups(back) == []
    assert back["warnings"] == []


@pytest.mark.parametrize("rcpt", [
    pytest.param("ietf-bounces@ietf.org", id="plain"),
    pytest.param("ietf-bounces+alice=example.com@ietf.org", id="verp"),
])
def test_unwrapped_bounce_left_alone(run, rcpt):
    report = run("--from", "MAILER-DAEMON@x.test", "-f", "", "--to", rcpt)
    assert report["recipients"] == [rcpt]
    assert not [a for a in report["milter_actions"] if a[0] in ("delrcpt", "addrcpt")]


def test_bounce_alongside_reply(run):
    """A list bounce and a wrapped reply in one message each take their own path."""
    report = run("--from", "MAILER-DAEMON@x.test", "-f", "",
                 "--to", f"ietf-bounces+a=x.test=40ietf.org@{FWD}",
                 f"alice=40example.com@{FWD}",
                 "--virtual", f"alice=40example.com@{FWD}")
    assert sorted(report["recipients"]) == ["alice@example.com", "ietf-bounces+a=x.test@ietf.org"]
    assert len(reply_lookups(report)) == 1
