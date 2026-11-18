"""DKIM1_MUNGE_FROM: the DMARC From rewrite, and turning it off.

On by default: From is wrapped for a p=reject/quarantine sender, as it
always has been.  Off, the rewriter relies on DKIM2: From is rewritten only
by the DKIM2 From rule (a list fan-out whose body changed since the last
DKIM2 signature), and no DMARC lookup is made."""
import pytest

import harness
from test_dkim2_milter import (AUTHOR, BODY, BOUNCES, FOOTER, MAILMAN, SUBSCRIBER,  # noqa: F401
                               UNSIGNED, author_post, dkim2, fields, keys, send,
                               through_mailman, verified)
from test_scenarios import ALIAS, FORWARDING_ADDR, REJECT, SENDER, WRAPPED, untouched


@pytest.mark.parametrize("value,expected", [
    (None, True), ("", True), ("yes", True), ("1", True), ("anything", True),
    ("no", False), ("NO", False), (" off ", False), ("false", False), ("0", False),
])
def test_setting_is_parsed(rewriter, value, expected):
    assert rewriter.munge_from_setting(value) is expected


def test_on_by_default(rewriter):
    assert rewriter.dkim1_munge_from is True


@pytest.fixture
def no_munge(rewriter, monkeypatch):
    monkeypatch.setattr(rewriter, "dkim1_munge_from", False)


def dmarc_lookups(report):
    return [q for q in report["dns_queries"] if q[0].startswith("_dmarc.")]


@pytest.mark.parametrize("policy", ["reject", "quarantine"])
def test_alias_keeps_from_and_writes_no_wrap(run, no_munge, policy):
    report = run("--from", SENDER, "--dmarc", f"example.com={policy}", *ALIAS)
    assert report["header_from"] == SENDER
    assert report["db_writes"] == []
    assert dmarc_lookups(report) == []


def test_alias_still_rewrites_the_envelope_for_spf(run, no_munge):
    report = run("--from", SENDER, *REJECT, "--spf", "example.com=-all", *ALIAS)
    assert report["header_from"] == SENDER
    assert report["envelope_from"] == FORWARDING_ADDR


def test_fall_through_keeps_from(run, no_munge):
    report = run("--from", SENDER, *REJECT, "--to", "bob@other.test", "--auth", "someone@ietf.org")
    assert report["header_from"] == SENDER
    assert report["db_writes"] == []
    assert dmarc_lookups(report) == []


def test_null_sender_fall_through_untouched(run, no_munge):
    report = run("--from", SENDER, "-f", "", *REJECT, "--to", "bob@other.test",
                 "--auth", "someone@ietf.org")
    assert untouched(report, env_from="")


def test_default_still_munges(run):
    report = run("--from", SENDER, *REJECT, *ALIAS)
    assert report["header_from"] == WRAPPED


def test_fanout_with_footer_still_gets_our_from(dkim2, keys, monkeypatch):
    monkeypatch.setattr(dkim2, "dkim1_munge_from", False)
    out, body = through_mailman(fields(("X-DKIM2-Arrival", "pass")) + author_post(keys))
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_unsigned_post_keeps_the_authors_from(dkim2, monkeypatch):
    monkeypatch.setattr(dkim2, "dkim1_munge_from", False)
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    dkim2._policy_cache.clear()
    sent = send(dkim2, fields(*UNSIGNED), BODY + FOOTER, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{AUTHOR}>"
