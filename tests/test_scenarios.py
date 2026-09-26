"""Routing through eom(): local lists, virtual aliases, local senders, the
fall-through branch, and null senders on each rewriting path."""
import pytest

FWD = "dmarc.ietf.org"
FORWARDING_ADDR = f"forwardingalgorithm@{FWD}"
SENDER = "alice@example.com"
WRAPPED = f"alice=40example.com@{FWD}"
REJECT = ("--dmarc", "example.com=reject")
ALIAS = ("--to", "alias@ietf.org", "--virtual", "alias@ietf.org")


def untouched(report, env_from=SENDER, header_from=SENDER):
    return (report["result"] == "ACCEPT"
            and report["envelope_from"] == env_from
            and report["header_from"] == header_from
            and report["db_writes"] == [])


# --- scenario 2: local list recipient ------------------------------------------

@pytest.mark.parametrize("to", [
    pytest.param(["ietf@ietf.org"], id="default-list"),
    pytest.param(["TestList@IETF.org"], id="mixed-case"),
    pytest.param(["testlist@ietf.org", "bob@other.test"], id="with-external"),
])
def test_local_list_recipient_untouched(run, to):
    assert untouched(run("--from", SENDER, *REJECT, "--to", *to))


def test_extra_local_list(run):
    assert untouched(run("--from", SENDER, *REJECT, "--to", "other@ietf.org",
                         "--local-list", "other@ietf.org"))
    # without it, other@ietf.org is just an external-looking recipient
    assert run("--from", SENDER, *REJECT, "--to", "other@ietf.org")["header_from"] == WRAPPED


# --- scenario 2: virtual alias recipient ----------------------------------------

def test_alias_dmarc(run):
    report = run("--from", SENDER, *REJECT, *ALIAS)
    assert report["envelope_from"] == FORWARDING_ADDR
    assert report["header_from"] == WRAPPED
    assert [w["email"] for w in report["db_writes"]] == [WRAPPED]


def test_alias_spf_only(run):
    report = run("-f", "bounces@mailer.example.net", "--from", SENDER,
                 "--spf", "mailer.example.net=-all", *ALIAS)
    assert report["envelope_from"] == FORWARDING_ADDR
    assert report["header_from"] == SENDER
    assert report["db_writes"] == []


@pytest.mark.parametrize("spf", ["?all", "+all", "nxdomain"])
def test_alias_spf_passes_untouched(run, spf):
    report = run("-f", "bounces@mailer.example.net", "--from", SENDER,
                 "--spf", f"mailer.example.net={spf}", *ALIAS)
    assert untouched(report, env_from="bounces@mailer.example.net")


def test_alias_local_envelope_skips_spf(run):
    report = run("-f", "carol@ietf.org", "--from", SENDER, "--spf", "ietf.org=-all", *ALIAS)
    assert untouched(report, env_from="carol@ietf.org")
    assert not [d for d in report["dns_lookups"] if d[0] == "spf"]


def test_alias_null_sender(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@example.com", *REJECT, *ALIAS)
    assert report["envelope_from"] == ""
    assert report["header_from"] == f"MAILER-DAEMON=40example.com@{FWD}"
    assert report["db_writes"] == []
    assert not [a for a in report["milter_actions"] if a[0] == "chgfrom"]


def test_alias_null_sender_spf_only(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@example.com",
                 "--spf", "example.com=-all", *ALIAS)
    assert untouched(report, env_from="", header_from="MAILER-DAEMON@example.com")
    assert not [d for d in report["dns_lookups"] if d[0] == "spf"]


# --- scenario 3: local sender ---------------------------------------------------

def test_local_sender_untouched(run):
    report = run("-f", "carol@ietf.org", "--from", "Carol <carol@ietf.org>",
                 "--dmarc", "ietf.org=reject", "--to", "bob@other.test")
    assert untouched(report, env_from="carol@ietf.org", header_from="Carol <carol@ietf.org>")


def test_local_envelope_external_from_is_not_scenario_3(run):
    report = run("-f", "carol@ietf.org", "--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["header_from"] == WRAPPED
    assert report["envelope_from"] == f"carol=40ietf.org@{FWD}"


# --- fall-through -----------------------------------------------------------------

@pytest.mark.parametrize("dmarc, spf", [
    pytest.param("none", "?all", id="no-policy"),
    pytest.param("nxdomain", "nxdomain", id="no-records"),
    pytest.param("none", "+all", id="spf-pass-all"),
])
def test_fall_through_no_change(run, dmarc, spf):
    report = run("--from", SENDER, "--dmarc", f"example.com={dmarc}",
                 "--spf", f"example.com={spf}", "--to", "bob@other.test")
    assert untouched(report)
    assert report["milter_actions"] == []


def test_fall_through_rewrite_domain_map(run):
    # an envelope in a REWRITE_DOMAINS domain wraps into its mapped domain
    report = run("-f", "someone@ietf.org", "--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["envelope_from"] == f"someone=40ietf.org@{FWD}"


def test_fall_through_null_sender_dmarc(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@example.com", *REJECT, "--to", "bob@other.test")
    assert report["envelope_from"] == ""
    assert report["header_from"] == f"MAILER-DAEMON=40example.com@{FWD}"
    assert report["db_writes"] == []
    assert not [a for a in report["milter_actions"] if a[0] == "chgfrom"]


def test_fall_through_null_sender_spf(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@example.com",
                 "--spf", "example.com=-all", "--to", "bob@other.test")
    assert untouched(report, env_from="", header_from="MAILER-DAEMON@example.com")


def test_fall_through_spf_softfail(run):
    report = run("-f", "b@mailer.example.net", "--from", SENDER,
                 "--spf", "mailer.example.net=~all", "--to", "bob@other.test")
    assert report["envelope_from"] == f"b=40mailer.example.net@{FWD}"
    assert report["header_from"] == SENDER


def test_dmarc_quarantine_wraps(run):
    report = run("--from", SENDER, "--dmarc", "example.com=quarantine", "--to", "bob@other.test")
    assert report["header_from"] == WRAPPED
