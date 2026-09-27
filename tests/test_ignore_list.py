"""IGNORELIST: recipients whose messages are never rewritten.

A single message with any ignored recipient is accepted unchanged, whether
the recipient is external or a virtual alias.  A mailman fan-out is decided
by its sender alone, so an ignored subscriber doesn't exempt the batch.
Matching is on the whole address, ignoring case and quoting.
"""
import pytest

FWD = "dmarc.ietf.org"
SENDER = "alice@example.com"
WRAPPED_SENDER = f"alice=40example.com@{FWD}"


@pytest.fixture
def send(run):
    """A message from a p=reject sender, so anything not ignored is rewritten."""
    def _send(*to, ignore=(), extra=()):
        args = ["--from", SENDER, "--dmarc", "example.com=reject", "--to", *to, *extra]
        for addr in ignore:
            args += ["--ignore", addr]
        return run(*args)
    return _send


def unchanged(report):
    return (report["result"] == "ACCEPT"
            and report["header_from"] == SENDER
            and report["envelope_from"] == SENDER
            and report["db_writes"] == [])


# --- parsing ------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    pytest.param("ign@x.test", {"ign@x.test"}, id="single"),
    pytest.param("a@x.test,b@y.test", {"a@x.test", "b@y.test"}, id="several"),
    pytest.param(" a@x.test , b@y.test ", {"a@x.test", "b@y.test"}, id="spaces"),
    pytest.param("A@X.Test,b@Y.TEST", {"a@x.test", "b@y.test"}, id="case"),
    pytest.param("a@x.test,,b@y.test,", {"a@x.test", "b@y.test"}, id="empty-entries"),
    pytest.param("a@x.test,A@x.test", {"a@x.test"}, id="duplicates"),
    pytest.param("", set(), id="empty"),
    pytest.param(" , ", set(), id="only-separators"),
])
def test_parse_ignore_list(rewriter, value, expected):
    assert rewriter.parse_ignore_list(value) == expected


# --- single messages ------------------------------------------------------------

def test_not_ignored_is_rewritten(send):
    # control: without the ignore list the same message is rewritten
    report = send("ign@x.test")
    assert report["header_from"] == WRAPPED_SENDER
    assert report["envelope_from"] == WRAPPED_SENDER


@pytest.mark.parametrize("rcpt, ignore", [
    pytest.param("ign@x.test", "ign@x.test", id="exact"),
    pytest.param("IGN@X.Test", "ign@x.test", id="upper-recipient"),
    pytest.param("ign@x.test", "IGN@X.TEST", id="upper-entry"),
    pytest.param('"ign"@x.test', "ign@x.test", id="quoted-recipient"),
    pytest.param('"j smith"@x.test', "J Smith@x.test", id="quoted-space"),
])
def test_ignored_recipient(send, rcpt, ignore):
    report = send(rcpt, ignore=[ignore])
    assert unchanged(report)
    assert report["ignored_recipients"] == [rcpt]


def test_one_ignored_recipient_exempts_message(send):
    report = send("ign@x.test", "bob@y.test", ignore=["ign@x.test"])
    assert unchanged(report)


def test_any_entry_of_several(send):
    report = send("b@y.test", ignore=["a@x.test", "b@y.test", "c@z.test"])
    assert unchanged(report)


@pytest.mark.parametrize("ignore", [
    pytest.param("x.test", id="domain-only"),
    pytest.param("@x.test", id="at-domain"),
    pytest.param("gn@x.test", id="suffix"),
    pytest.param("ign@x.tes", id="prefix"),
    pytest.param("ign@sub.x.test", id="subdomain"),
    pytest.param("ign", id="local-only"),
])
def test_whole_address_only(send, ignore):
    report = send("ign@x.test", ignore=[ignore])
    assert report["header_from"] == WRAPPED_SENDER
    assert report["ignored_recipients"] == []


def test_ignored_virtual_alias(send):
    virtual = ["--virtual", "alias@ietf.org"]
    rewritten = send("alias@ietf.org", extra=virtual)
    assert rewritten["envelope_from"] == "forwardingalgorithm@dmarc.ietf.org"
    assert unchanged(send("alias@ietf.org", ignore=["alias@ietf.org"], extra=virtual))


def test_ignored_spf_only(run):
    args = ["-f", "bounces@mailer.example.net", "--from", SENDER,
            "--spf", "mailer.example.net=-all", "--to", "ign@x.test"]
    assert run(*args)["envelope_from"] == "bounces=40mailer.example.net@dmarc.ietf.org"
    assert run(*args, "--ignore", "ign@x.test")["envelope_from"] == "bounces@mailer.example.net"


def test_ignored_null_sender(run):
    report = run("-f", "", "--from", "MAILER-DAEMON@example.com", "--dmarc", "example.com=reject",
                 "--to", "ign@x.test", "--ignore", "ign@x.test")
    assert report["header_from"] == "MAILER-DAEMON@example.com"
    assert report["envelope_from"] == ""


def test_ignore_list_does_not_stop_unwrap(run):
    # replies to wrapped senders are unwrapped before the ignore list is checked
    wrapped = f"carol=40other.test@{FWD}"
    report = run("--from", "bob@y.test", "--to", wrapped, "--virtual", wrapped,
                 "--ignore", wrapped, "--ignore", "carol@other.test")
    assert report["recipients"] == ["carol@other.test"]


def test_empty_ignore_list(send):
    report = send("ign@x.test", ignore=[""])
    assert report["ignore_list"] == []
    assert report["header_from"] == WRAPPED_SENDER


# --- mailman fan-outs --------------------------------------------------------------

def test_fanout_ignored_subscriber_does_not_exempt_batch(send):
    report = send("a@x.test", "ign@x.test", ignore=["ign@x.test"], extra=["--list", "ietf@ietf.org"])
    assert report["mode"] == "list fan-out"
    assert report["header_from"] == WRAPPED_SENDER
    assert report["envelope_from"] == f"ietf-bounces=40ietf.org@{FWD}"


def test_fanout_all_subscribers_ignored(send):
    report = send("ign@x.test", ignore=["ign@x.test"], extra=["--list", "ietf@ietf.org"])
    assert report["header_from"] == WRAPPED_SENDER


def test_ignore_list_is_per_run(send):
    # the harness applies --ignore to each run; nothing carries over
    assert unchanged(send("ign@x.test", ignore=["ign@x.test"]))
    assert send("ign@x.test")["header_from"] == WRAPPED_SENDER
