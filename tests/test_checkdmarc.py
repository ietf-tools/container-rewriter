"""DMARC and SPF policy as the real checkdmarc reads it.

The harness serves --dmarc/--spf pins as DNS records (harness.FakeDNS), so
these go through checkdmarc's own parsing, DMARCbis tree walk and retries.
"""
import pytest

FWD = "dmarc.ietf.org"
SENDER = "alice@example.com"
WRAPPED = f"alice=40example.com@{FWD}"
EXTERNAL = ("--to", "bob@other.test")


def wraps_from(report):
    return report["header_from"] == WRAPPED


@pytest.mark.parametrize("record", [
    pytest.param("v=DMARC1; p=reject", id="minimal"),
    pytest.param("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=s", id="reporting"),
    pytest.param("v=DMARC1;p=quarantine;sp=none", id="no-spaces"),
    pytest.param("v=DMARC1; p=reject; np=reject; t=n", id="dmarcbis-tags"),
])
def test_whole_record(run, record):
    assert wraps_from(run("--from", SENDER, "--dmarc", f"example.com={record}", *EXTERNAL))


@pytest.mark.parametrize("record", [
    pytest.param("v=DMARC1; p=none; rua=mailto:dmarc@example.com", id="p-none"),
    pytest.param("v=DMARC1; p=none; sp=reject", id="sp-is-for-subdomains"),
])
def test_whole_record_no_policy(run, record):
    assert not wraps_from(run("--from", SENDER, "--dmarc", f"example.com={record}", *EXTERNAL))


@pytest.mark.parametrize("sender, wrapped", [
    ("alice@lists.example.com", True),
    ("alice@a.b.example.com", True),
    ("alice@example.com", False),
])
def test_subdomain_takes_parent_sp(run, sender, wrapped):
    report = run("--from", sender, "--dmarc", "example.com=p=none;sp=reject", *EXTERNAL)
    assert (report["header_from"] != sender) is wrapped


def test_subdomain_own_record_wins(run):
    report = run("--from", "alice@lists.example.com", *EXTERNAL,
                 "--dmarc", "example.com=reject", "--dmarc", "lists.example.com=none")
    assert report["header_from"] == "alice@lists.example.com"


@pytest.mark.parametrize("record", [
    pytest.param("v=spf1 ip4:192.0.2.0/24 -all", id="ip4"),
    pytest.param("v=spf1 ip4:192.0.2.0/24 ~all", id="softfail"),
    pytest.param("v=spf1 redirect=_spf.mailer.example.net", id="redirect"),
])
def test_whole_spf_record(run, record):
    report = run("-f", "b@mailer.example.net", "--from", SENDER, *EXTERNAL,
                 "--spf", f"mailer.example.net={record}",
                 "--spf", "_spf.mailer.example.net=v=spf1 -all")
    assert report["envelope_from"] == f"b=40mailer.example.net@{FWD}"


def test_spf_neutral_untouched(run):
    report = run("-f", "b@mailer.example.net", "--from", SENDER, *EXTERNAL,
                 "--spf", "mailer.example.net=v=spf1 ip4:192.0.2.0/24 ?all")
    assert report["envelope_from"] == "b@mailer.example.net"


def test_timeout_is_retried(run):
    # rewriter asks for two retries: three queries before giving up
    report = run("--from", SENDER, "--dmarc", "example.com=timeout", *EXTERNAL)
    assert [q for q in report["dns_queries"] if q[0] == "_dmarc.example.com"] == \
        [["_dmarc.example.com", "TXT", "timeout"]] * 3


def test_no_live_dns(run):
    report = run("--from", SENDER, "--dmarc", "example.com=reject", *EXTERNAL)
    assert report["dns_queries"]
    assert not [q for q in report["dns_queries"] if q[2] == "live DNS"]


# receivers ignore an unknown tag or a bad report URI and still apply p=
# (RFC 7489 6.3), but checkdmarc refuses the whole record, so the rewriter
# sees no policy and forwards mail that will be rejected
@pytest.mark.xfail(strict=True, reason="a record checkdmarc can't parse counts as no policy")
@pytest.mark.parametrize("record", [
    pytest.param("v=DMARC1; p=reject; foo=bar", id="unknown-tag"),
    pytest.param("v=DMARC1; p=reject; rua=dmarc@example.com", id="rua-without-mailto"),
    pytest.param("v=DMARC1; p=reject; pct=abc", id="bad-pct"),
])
def test_unparseable_record_still_enforced(run, record):
    assert wraps_from(run("--from", SENDER, "--dmarc", f"example.com={record}", *EXTERNAL))
