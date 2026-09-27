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


# --- fall-through: bounces to a wrapped envelope sender -------------------------

VERP = "b-123@mailer.example.net"
VERP_WRAPPED = f"b-123=40mailer.example.net@{FWD}"


def wrap_row(email_addr, destination):
    return {"table": "virtual", "email": email_addr, "destination": destination}


def test_fall_through_spf_only_records_envelope_wrap(run):
    report = run("-f", VERP, "--from", SENDER,
                 "--spf", "mailer.example.net=-all", "--to", "bob@other.test")
    assert report["envelope_from"] == VERP_WRAPPED
    assert report["db_writes"] == [wrap_row(VERP_WRAPPED, VERP)]


def test_fall_through_dmarc_records_both_wraps(run):
    report = run("-f", VERP, "--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["envelope_from"] == VERP_WRAPPED
    assert report["header_from"] == WRAPPED
    assert report["db_writes"] == [wrap_row(WRAPPED, SENDER), wrap_row(VERP_WRAPPED, VERP)]


def test_fall_through_same_envelope_and_from_one_row(run):
    report = run("--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["db_writes"] == [wrap_row(WRAPPED, SENDER)]


def test_alias_forward_records_no_envelope_wrap(run):
    # an alias forward sends from FORWARDING_ADDR, which isn't a wrap
    report = run("-f", VERP, "--from", SENDER, "--spf", "mailer.example.net=-all", *ALIAS)
    assert report["envelope_from"] == FORWARDING_ADDR
    assert report["db_writes"] == []


@pytest.mark.parametrize("policy", [
    pytest.param(("--spf", "mailer.example.net=-all"), id="spf-only"),
    pytest.param(REJECT, id="dmarc"),
])
def test_bounce_to_envelope_wrap_round_trip(run, policy):
    """A DSN to the wrapped envelope sender goes back to the original one."""
    out = run("-f", VERP, "--from", SENDER, *policy, "--to", "bob@other.test")
    virtual = [w["email"] for w in out["db_writes"]]

    back = run("-f", "", "--from", "MAILER-DAEMON@other.test",
               "--to", out["envelope_from"], *[a for v in virtual for a in ("--virtual", v)])
    assert back["result"] == "ACCEPT"
    assert back["recipients"] == [VERP]
    assert back["envelope_from"] == ""


def test_bounce_to_unrecorded_envelope_wrap_refused(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@other.test", "--to", VERP_WRAPPED)
    assert report["result"] == "REJECT"
    assert report["recipients"] == []
