"""Failure handling: database errors, unexpected exceptions, chgfrom failures
and DNS timeouts."""
import pytest

import harness

FWD = "dmarc.ietf.org"
SENDER = "alice@example.com"
WRAPPED = f"alice=40example.com@{FWD}"
REJECT = ("--dmarc", "example.com=reject")


def raise_on(monkeypatch, fragment, exc):
    """Make the fake database raise exc for queries containing fragment."""
    orig = harness.FakeCursor.execute

    def execute(self, sql, params=()):
        if fragment in " ".join(sql.split()).lower():
            raise exc
        return orig(self, sql, params)
    monkeypatch.setattr(harness.FakeCursor, "execute", execute)


# --- database ---------------------------------------------------------------------

def test_db_down_tempfails(run):
    report = run("--db-down", "--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["result"] == "TEMPFAIL"
    assert report["reply"] == "451 4.3.0 backend unavailable"


def test_db_down_unwrap_still_unwraps(run):
    # the wrap lookup fails, and the recipient is unwrapped regardless
    wrapped = f"carol=40other.test@{FWD}"
    report = run("--db-down", "--from", "bob@y.test", "--to", wrapped)
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["carol@other.test"]


def test_unwrap_lookup_programming_error(run, rewriter, monkeypatch):
    import psycopg
    raise_on(monkeypatch, "email = %s", psycopg.ProgrammingError("relation does not exist"))
    wrapped = f"carol=40other.test@{FWD}"
    report = run("--from", "bob@y.test", "--to", wrapped, "--virtual", wrapped)
    assert report["result"] == "ACCEPT"
    assert report["recipients"] == ["carol@other.test"]


def test_unwrap_without_wrap_record(run):
    report = run("--from", "bob@y.test", "--to", f"carol=40other.test@{FWD}")
    assert report["recipients"] == ["carol@other.test"]


def test_wrap_log_write_failure_is_not_fatal(run, monkeypatch):
    import psycopg
    raise_on(monkeypatch, "insert into virtual", psycopg.OperationalError("connection lost"))
    # a fan-out skips the scenario 2 lookups, so the insert is the first query
    report = run("--list", "ietf@ietf.org", "--from", SENDER, *REJECT, "--to", "a@x.test")
    assert report["result"] == "ACCEPT"
    assert report["header_from"] == WRAPPED
    assert report["db_writes"] == []


def test_local_list_query_programming_error(run, monkeypatch):
    import psycopg
    raise_on(monkeypatch, "from mailman_lists", psycopg.ProgrammingError("relation does not exist"))
    report = run("--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["result"] == "TEMPFAIL"
    assert report["reply"] == "451 4.3.0 rewriter internal error"


# --- unexpected exceptions ------------------------------------------------------

def test_exception_before_queue_id(run, monkeypatch):
    orig = harness.FakeCtx.getsymval

    def getsymval(self, sym):
        if sym == "i":
            raise KeyError("i")
        return orig(self, sym)
    monkeypatch.setattr(harness.FakeCtx, "getsymval", getsymval)
    report = run("--from", SENDER, "--to", "bob@other.test")
    assert report["result"] == "TEMPFAIL"
    assert report["reply"] == "451 4.3.0 rewriter internal error"
    assert report["exception"] is None


def test_exception_after_changes_tempfails(run, rewriter, monkeypatch):
    # the From header is already changed when this fails; TEMPFAIL makes the
    # MTA drop the change rather than accept a half-rewritten message
    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(rewriter, "update_addr_wrap_log", boom)
    report = run("--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["result"] == "TEMPFAIL"
    assert report["reply"] == "451 4.3.0 rewriter internal error"
    assert [a[0] for a in report["milter_actions"]] == ["chgheader"]


# --- chgfrom failures -------------------------------------------------------------

@pytest.fixture
def chgfrom_fails(monkeypatch):
    def chgfrom(self, sender, params=None):
        raise RuntimeError("chgfrom not negotiated")
    monkeypatch.setattr(harness.FakeCtx, "chgfrom", chgfrom)


def test_chgfrom_failure_spf_only_is_logged(run, chgfrom_fails):
    report = run("-f", "b@mailer.example.net", "--from", SENDER,
                 "--spf", "mailer.example.net=-all", "--to", "bob@other.test")
    assert report["result"] == "ACCEPT"
    assert report["envelope_from"] == "b@mailer.example.net"


def test_chgfrom_failure_dmarc_tempfails(run, chgfrom_fails):
    # unlike the SPF-only path, the DMARC path doesn't catch chgfrom errors
    report = run("--from", SENDER, *REJECT, "--to", "bob@other.test")
    assert report["result"] == "TEMPFAIL"


# --- DNS timeouts and the policy cache ---------------------------------------------

@pytest.fixture
def dns(rewriter, monkeypatch):
    """Point rewriter at pinned DNS answers and return the lookup log."""
    def _dns(dmarc=None, spf=None):
        fake = harness.FakeCheckdmarc(harness._stub_checkdmarc(), dmarc or {}, spf or {}, no_dns=True)
        monkeypatch.setattr(rewriter, "checkdmarc", fake)
        rewriter._policy_cache.clear()
        return fake.lookups
    return _dns


def test_policy_is_cached(rewriter, dns):
    lookups = dns(dmarc={"example.com": "reject"})
    assert rewriter.check_dmarc("a@example.com") is True
    assert rewriter.check_dmarc("b@Example.COM") is True
    assert len(lookups) == 1


def test_no_policy_is_cached(rewriter, dns):
    lookups = dns(dmarc={"example.com": "none"})
    assert rewriter.check_dmarc("a@example.com") is False
    assert rewriter.check_dmarc("a@example.com") is False
    assert len(lookups) == 1


@pytest.mark.parametrize("check, kind", [("check_dmarc", "dmarc"), ("check_spf", "spf")])
def test_timeout_is_not_cached(rewriter, dns, check, kind):
    lookups = dns(**{kind: {"example.com": "timeout"}})
    assert getattr(rewriter, check)("a@example.com") is False
    assert getattr(rewriter, check)("a@example.com") is False
    assert len(lookups) == 2
    assert (kind, "example.com") not in rewriter._policy_cache


@pytest.mark.parametrize("check, kind", [("check_dmarc", "dmarc"), ("check_spf", "spf")])
def test_lifetime_timeout_is_not_cached(rewriter, dns, check, kind):
    # "The resolution lifetime expired after ...", without "timed out"
    lookups = dns(**{kind: {"example.com": "timeout-empty"}})
    assert getattr(rewriter, check)("a@example.com") is False
    assert getattr(rewriter, check)("a@example.com") is False
    assert len(lookups) == 2
    assert (kind, "example.com") not in rewriter._policy_cache


@pytest.mark.parametrize("check, kind", [("check_dmarc", "dmarc"), ("check_spf", "spf")])
def test_servfail_is_not_cached(rewriter, dns, check, kind):
    lookups = dns(**{kind: {"example.com": "servfail"}})
    assert getattr(rewriter, check)("a@example.com") is False
    assert getattr(rewriter, check)("a@example.com") is False
    assert len(lookups) == 2
    assert (kind, "example.com") not in rewriter._policy_cache


def test_servfail_means_no_rewrite(run, rewriter):
    report = run("--from", SENDER, "--dmarc", "example.com=servfail", "--to", "bob@other.test")
    assert report["header_from"] == SENDER
    assert ("dmarc", "example.com") not in rewriter._policy_cache


@pytest.mark.parametrize("failure", ["nxdomain"])
def test_other_dns_failures_are_cached(rewriter, dns, failure):
    lookups = dns(dmarc={"example.com": failure})
    rewriter.check_dmarc("a@example.com")
    rewriter.check_dmarc("a@example.com")
    assert len(lookups) == 1


def test_timeout_means_no_rewrite(run, rewriter):
    # current behaviour: a DMARC timeout is treated as "no policy"
    report = run("--from", SENDER, "--dmarc", "example.com=timeout", "--to", "bob@other.test")
    assert report["header_from"] == SENDER
    assert ("dmarc", "example.com") not in rewriter._policy_cache
