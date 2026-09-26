import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import harness  # noqa: E402

# pin the configuration so the tests don't depend on the caller's environment
os.environ.update(harness.DEFAULT_ENV)
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["LOGGING_FILENAME"] = os.path.join(tempfile.mkdtemp(prefix="rewriter-tests-"), "rewrite.log")


@pytest.fixture(scope="session")
def rewriter():
    harness.install_stubs()
    import rewriter
    return rewriter


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
