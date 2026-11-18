import base64
import json
import os
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import harness  # noqa: E402

# pin the configuration so the tests don't depend on the caller's environment
os.environ.update(harness.DEFAULT_ENV)
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["LOGGING_FILENAME"] = os.path.join(tempfile.mkdtemp(prefix="rewriter-tests-"), "rewrite.log")


_real = {}


@pytest.fixture(scope="session")
def rewriter():
    harness.install_stubs()
    import rewriter
    # harness.main() swaps in its fake database for good; keep the real one
    _real["get_db_pool"] = rewriter.get_db_pool
    return rewriter


@pytest.fixture
def get_db_pool(rewriter, monkeypatch):
    """The real get_db_pool(), with no pool built yet."""
    monkeypatch.setattr(rewriter, "_db_pool", None)
    return _real["get_db_pool"]


@pytest.fixture
def run(rewriter, capsys):
    """Run one message through the harness and return its JSON report."""
    def _run(*args):
        # DMARC/SPF answers are cached per domain; each test pins its own
        rewriter._policy_cache.clear()
        capsys.readouterr()
        assert harness.main(["--json", "--no-dns", "-q", *args]) == 0
        return json.loads(capsys.readouterr().out)
    return _run


# --- DKIM2 fixtures shared by the test_dkim2_* and test_verp modules ----------------

T = 1740000000          # the test messages' timestamp; the dkim2 fixture's clock
SIGN = "DKIM2-SIGN"     # the signing pass's {daemon_name}


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    keydir = tmp_path_factory.mktemp("keys")
    dns = {}
    for domain in ("example.com", "ietf.org"):
        key = ed25519.Ed25519PrivateKey.generate()
        os.makedirs(keydir / domain)
        (keydir / domain / "sel1.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        dns[domain] = {"sel1._domainkey": [["txt", f"v=DKIM1; k=ed25519; p={public}"]]}
    return str(keydir), dns


@pytest.fixture
def dkim2(rewriter, keys, monkeypatch):
    """The rewriter with DKIM2 configured, no DMARC or SPF policy anywhere,
    and a clock near the test messages' timestamps."""
    import time
    keydir, dns = keys
    monkeypatch.setattr(time, "time", lambda: T + 60)
    monkeypatch.setattr(rewriter, "dkim2_keydir", keydir)
    monkeypatch.setattr(rewriter, "dkim2_selector", "sel1")
    monkeypatch.setattr(rewriter, "dkim2_authserv_id", "mail.ietf.org")
    monkeypatch.setattr(rewriter, "dkim2_dns", dns)
    monkeypatch.setattr(rewriter, "checkdmarc",
                        harness.LoggedCheckdmarc(harness.FakeDNS({}, {}, True)))
    monkeypatch.setattr(rewriter, "get_db_pool", lambda: harness.FakeDB(virtual=(), down=False))
    rewriter._policy_cache.clear()
    return rewriter


@pytest.fixture
def split(dkim2, monkeypatch):
    monkeypatch.setattr(dkim2, "dkim2_sign_daemon", SIGN)
    return dkim2
