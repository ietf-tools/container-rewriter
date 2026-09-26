"""format_from_header(): the rewritten From header (RFC 5322, 2047, 6532).

The display name is decoded to text, stripped of control characters (so an
encoded CR/LF can't start a new header line), then quoted when it has
specials, RFC 2047 encoded when it's non-ASCII (encoded-words of at most 75
characters), or left as raw UTF-8 when the address itself is UTF-8.
"""
import email.utils
import re
from email.header import decode_header, make_header

import pytest

A = "alice=40example.com@dmarc.ietf.org"
U = "josé=40exämple.com@dmarc.ietf.org"


def decoded_name(header):
    name, _addr = email.utils.parseaddr(header)
    return str(make_header(decode_header(name)))


@pytest.mark.parametrize("name, addr, expected", [
    pytest.param("", A, A, id="no-name"),
    pytest.param("Alice Smith", A, f"Alice Smith <{A}>", id="plain"),
    pytest.param("Smith, Alice", A, f'"Smith, Alice" <{A}>', id="comma-quoted"),
    pytest.param("A. Smith", A, f'"A. Smith" <{A}>', id="dot-quoted"),
    pytest.param('Alice "Al" Smith', A, f'"Alice \\"Al\\" Smith" <{A}>', id="inner-quotes"),
    pytest.param("back\\slash", A, f'"back\\\\slash" <{A}>', id="backslash"),
    pytest.param("=?utf-8?q?Jos=C3=A9?=", A, f"=?utf-8?b?Sm9zw6k=?= <{A}>", id="encoded-word"),
    pytest.param("José Müller", A, f"=?utf-8?b?Sm9zw6kgTcO8bGxlcg==?= <{A}>", id="raw-utf8-name"),
    pytest.param("  Alice \t Smith  ", A, f"Alice Smith <{A}>", id="whitespace-collapsed"),
    pytest.param(" \t ", A, A, id="whitespace-only"),
    pytest.param("=?utf-8?q?a=0D=0ABcc=3A_evil?=", A, f'"a Bcc: evil" <{A}>', id="encoded-crlf"),
    pytest.param("a\r\nBcc: evil", A, f'"a Bcc: evil" <{A}>', id="raw-crlf"),
    pytest.param("=?utf-8?q?=00=07=1B?=", A, A, id="only-control-chars"),
    pytest.param("José", U, f"José <{U}>", id="utf8-address"),
    pytest.param("Müller, José", U, f'"Müller, José" <{U}>', id="utf8-address-quoted"),
    pytest.param('J "Q" Müller', U, f'"J \\"Q\\" Müller" <{U}>', id="utf8-address-inner-quotes"),
    pytest.param("Alice", U, f"Alice <{U}>", id="ascii-name-utf8-address"),
    pytest.param("=?x-unknown?q?abc?=", A, f"=?x-unknown?q?abc?= <{A}>", id="unknown-charset"),
])
def test_format_from_header(rewriter, name, addr, expected):
    assert rewriter.format_from_header(name, addr) == expected


@pytest.mark.parametrize("name", [
    "Alice Smith", "Smith, Alice", 'Alice "Al" Smith', "José Müller",
    "=?utf-8?q?Jos=C3=A9?=", "Ünïcödé " * 12, "日本語の名前 " * 8,
])
def test_round_trips(rewriter, name):
    header = rewriter.format_from_header(name, A)
    assert email.utils.parseaddr(header)[1] == A
    assert decoded_name(header) == " ".join(str(make_header(decode_header(name))).split())


@pytest.mark.parametrize("name", ["Ünïcödé " * 12, "日本語の名前 " * 8, "é" * 200])
def test_long_names_split_into_short_encoded_words(rewriter, name):
    header = rewriter.format_from_header(name, A)
    words = re.findall(r"=\?[^?]+\?[bq]\?[^?]*\?=", header, re.IGNORECASE)
    assert len(words) > 1
    assert all(len(w) <= 75 for w in words)


@pytest.mark.parametrize("name", [
    "=?utf-8?q?a=0D=0ABcc=3A_evil?=", "=?utf-8?b?YQ0KQmNjOiBldmls?=",
    "a\r\nBcc: evil", "a\nb", "a\rb", "tab\there", "nul\x00byte",
])
def test_no_control_characters(rewriter, name):
    for addr in (A, U):
        header = rewriter.format_from_header(name, addr)
        assert not re.search(r"[\x00-\x1f\x7f]", header)


@pytest.mark.parametrize("from_header, expected", [
    pytest.param("Alice Smith <alice@example.com>", f"Alice Smith <{A}>", id="plain"),
    pytest.param('"Smith, Alice" <alice@example.com>', f'"Smith, Alice" <{A}>', id="quoted"),
    pytest.param("=?utf-8?q?Jos=C3=A9?= <alice@example.com>", f"=?utf-8?b?Sm9zw6k=?= <{A}>", id="encoded"),
    pytest.param("=?utf-8?q?a=0D=0ABcc=3A_evil?= <alice@example.com>", f'"a Bcc: evil" <{A}>', id="crlf"),
    pytest.param("alice@example.com (Alice Smith)", f"Alice Smith <{A}>", id="comment-name"),
])
def test_through_milter(run, from_header, expected):
    report = run("--from", from_header, "--to", "bob@other.test", "--dmarc", "example.com=reject")
    assert report["header_from"] == expected
