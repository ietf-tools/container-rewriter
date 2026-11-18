"""DKIM2 through the milter: verifying on arrival, the From rule on a list
fan-out, and the Message-Instance and DKIM2-Signature added on the way out."""
import base64
import email.utils
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import dkim2hop
import harness

T = 1740000000
LIST = "ietf@ietf.org"
BOUNCES = "ietf-bounces@ietf.org"
MAILMAN = "mailman@ietf.org"
AUTHOR = "alice@example.com"
WRAPPED = "alice=40example.com@dmarc.ietf.org"
SUBSCRIBER = "sub@example.net"
BODY = b"Hello.\r\n"
FOOTER = b"-- \r\nietf mailing list\r\n"


class Ctx(harness.FakeCtx):
    def addheader(self, field, value, idx=-1):
        self.actions.append(("addheader", field, value, idx))


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


class Sent:
    """A message after the milter's changes: what the next hop receives."""

    def __init__(self, result, actions, fields, body, mail_from, rcpts):
        self.result = result
        self.actions = actions
        self.body = body
        self.mail_from = mail_from
        self.rcpts = list(rcpts)
        fields = list(fields)
        for action in actions:
            if action[0] == "chgfrom":
                self.mail_from = action[1]
            elif action[0] == "delrcpt":
                self.rcpts.remove(email.utils.parseaddr(action[1])[1])
            elif action[0] == "addrcpt":
                self.rcpts.append(email.utils.parseaddr(action[1])[1])
            elif action[0] == "chgheader":
                _a, name, idx, value = action
                at = [i for i, f in enumerate(fields)
                      if dkim2hop._name(f) == name.lower().encode()][max(idx, 1) - 1]
                if value is None:
                    del fields[at]
                else:
                    fields[at] = dkim2hop.header_field(name, value)
            elif action[0] == "addheader":
                _a, name, value, idx = action
                field = dkim2hop.header_field(name, value)
                if idx < 0:
                    fields.append(field)
                else:
                    fields.insert(idx, field)
        self.fields = fields

    def named(self, name):
        return [f for f in self.fields if dkim2hop._name(f) == name.lower().encode()]

    def value(self, name):
        found = self.named(name)
        return found[0].split(b":", 1)[1].strip().decode() if found else None

    def tag(self, name, tag):
        import re
        value = b"".join(self.named(name)[0].split(b":", 1)[1].split()).decode()
        m = re.search(rf"(?:^|;){tag}=([^;]*)", value)
        return m.group(1) if m else None


def send(rewriter, fields, body, mail_from, rcpts, auth=None):
    """One message through the milter, as Postfix drives it."""
    ctx = Ctx({"i": "TEST01", "{auth_authen}": auth})
    m = rewriter.EnvelopeMilter()
    m._ctx = ctx
    if hasattr(m, "_setctx"):
        m._setctx(ctx)
    import Milter
    m._actions = Milter.CURR_ACTS
    m.envfrom(f"<{mail_from}>")
    for r in rcpts:
        m.envrcpt(f"<{r}>")
    for field in fields:
        name, value = field.split(b":", 1)
        # as libmilter hands a field over: no line break at the end, LF inside
        m.header(name.decode(), value.strip().replace(b"\r\n", b"\n").decode("utf-8", "surrogateescape"))
    m.eoh()
    for i in range(0, len(body), 5):       # in pieces, as a milter gets it
        m.body(body[i:i + 5])
    result = m.eom()
    return Sent(result, ctx.actions, fields, body, mail_from, rcpts)


def fields(*pairs):
    return [dkim2hop.header_field(n, v) for n, v in pairs]


def author_post(keys, sender=AUTHOR):
    """A post as the author's server sends it to the list: i=1 by example.com."""
    keydir, dns = keys
    plain = fields(("From", f"Alice <{sender}>"), ("To", LIST), ("Subject", "hello"))
    signed = dkim2hop.sign(dkim2hop.stream(plain, BODY, dns=dns, arriving=False), plain,
                           sender, [LIST], keydir, timestamp=T)
    assert signed, signed.reason
    return fields(*signed.insert) + plain


def through_mailman(arrived, footer=FOOTER, instance=True, null_body=False):
    """What a list manager that records its own changes sends back to us for
    fan-out: a subject tag, a List-Id, perhaps a footer, and an unsigned
    Message-Instance that says so (the next after any the post came with).
    null_body: it rewrote the body and says only that, with a null body
    Recipe.  instance=False is stock Mailman, which records nothing."""
    out = []
    for f in arrived:
        if dkim2hop._name(f) == b"subject":
            f = dkim2hop.header_field("Subject", "[ietf] hello")
        out.append(f)
    out.append(dkim2hop.header_field("List-Id", "<ietf.ietf.org>"))
    body = BODY + footer
    if instance:
        bare = lambda fs: [f[:-2] for f in fs]          # noqa: E731
        recipe = dkim2hop.dkim2sign.build_recipes(bare(arrived), BODY, bare(out), body)
        if null_body:
            recipe["b"] = None
        version = 1 + len([f for f in arrived if dkim2hop._name(f) == b"message-instance"])
        mi = dkim2hop.dkim2sign.build_message_instance(
            bare(out), body, version=version, recipe=recipe if version > 1 else None)
        out = [mi.encode() + b"\r\n"] + out
    return out, body


def verified(dkim2, sent):
    return dkim2hop.verify(sent.fields, sent.body, sent.mail_from, sent.rcpts, dkim2.dkim2_dns)


# --- arrival -------------------------------------------------------------------

def test_arrival_is_verified_and_reported_not_signed(dkim2, keys):
    sent = send(dkim2, author_post(keys), BODY, AUTHOR, [LIST])
    assert sent.value("Authentication-Results").startswith("mail.ietf.org; dkim2=pass")
    assert sent.value("X-DKIM2-Arrival") == "pass"
    # delivered to mailman here: nothing to sign, nothing rewritten
    assert len(sent.named("DKIM2-Signature")) == 1
    assert sent.value("From") == f"Alice <{AUTHOR}>"
    assert dkim2.Milter.ACCEPT == sent.result


def test_arrival_failure_is_reported_and_the_message_still_accepted(dkim2, keys):
    sent = send(dkim2, author_post(keys), BODY + b"tampered\r\n", AUTHOR, [LIST])
    assert sent.result == dkim2.Milter.ACCEPT
    assert sent.value("Authentication-Results").startswith('mail.ietf.org; dkim2=fail reason="')
    assert sent.value("X-DKIM2-Arrival") == "fail"


def test_arrival_verdict_from_outside_is_replaced(dkim2, keys):
    forged = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    sent = send(dkim2, forged, BODY + b"tampered\r\n", AUTHOR, [LIST])
    assert [f.split(b":", 1)[1].strip() for f in sent.named("X-DKIM2-Arrival")] == [b"fail"]


def test_body_is_read_only_when_something_needs_it(dkim2, keys):
    plain = fields(("From", AUTHOR), ("To", LIST), ("Subject", "x"))

    def seen(header_fields, rcpts, auth=None):
        ctx = Ctx({"i": "TEST01", "{auth_authen}": auth})
        m = dkim2.EnvelopeMilter()
        m._ctx = ctx
        m.envfrom(f"<{AUTHOR}>")
        for r in rcpts:
            m.envrcpt(f"<{r}>")
        for field in header_fields:
            name, value = field.split(b":", 1)
            m.header(name.decode(), value.strip().decode())
        m.eoh()
        return m.seen

    # no Message-Instance, delivered here: nothing wants the body
    arriving = seen(plain, [LIST])
    assert not arriving.hashed and not arriving._verify_body
    # a chain to check: the body is hashed and verified
    signed = seen(author_post(keys), [LIST])
    assert signed.hashed and signed._verify_body
    # no Message-Instance, but relayed off-site: we may sign it, as m=1
    relayed = seen(plain, [SUBSCRIBER], auth=MAILMAN)
    assert relayed.hashed and not relayed._verify_body


def test_plain_mail_arrives_as_none(dkim2):
    plain = fields(("From", AUTHOR), ("To", LIST), ("Subject", "x"))
    sent = send(dkim2, plain, BODY, AUTHOR, [LIST])
    assert sent.value("Authentication-Results") == "mail.ietf.org; dkim2=none"
    assert sent.value("X-DKIM2-Arrival") == "none"


# --- header fields changed on arrival ---------------------------------------------

WRAP = "bob=40example.org@dmarc.ietf.org"
UNWRAPPED = "bob@example.org"


def to_list_and_wrap(keys, signed=True):
    """A post to the list and to one of our wrapped addresses."""
    keydir, dns = keys
    plain = fields(("From", f"Alice <{AUTHOR}>"), ("To", f"{LIST}, {WRAP}"), ("Subject", "hello"))
    if not signed:
        return plain
    made = dkim2hop.sign(dkim2hop.stream(plain, BODY, dns=dns, arriving=False), plain,
                         AUTHOR, [LIST, WRAP], keydir, timestamp=T)
    assert made, made.reason
    return fields(*made.insert) + plain


@pytest.fixture
def our_key_only(dkim2, keys, monkeypatch, tmp_path):
    """As deployed: a key for our domain, none for the author's."""
    import shutil
    keydir, _dns = keys
    post = to_list_and_wrap(keys)
    shutil.copytree(os.path.join(keydir, "ietf.org"), tmp_path / "ietf.org")
    monkeypatch.setattr(dkim2, "dkim2_keydir", str(tmp_path))
    monkeypatch.setattr(dkim2, "get_db_pool", lambda: harness.FakeDB(virtual=[WRAP], down=False))
    return post


def test_unwrapped_to_is_recorded_when_we_do_not_sign(dkim2, keys, our_key_only):
    """To is shown unwrapped, which changes a hashed field on every copy.
    Nothing makes us take the envelope over, so we have no key to sign
    with: the change goes into an unsigned instance instead, and the chain
    on the copy mailman gets still describes the message."""
    sent = send(dkim2, our_key_only, BODY, AUTHOR, [LIST, WRAP])
    assert sent.rcpts == [LIST, UNWRAPPED]
    assert sent.value("To") == f"{LIST}, {UNWRAPPED}"
    assert len(sent.named("DKIM2-Signature")) == 1
    assert [f.split(b";")[0].split(b"=")[1] for f in sent.named("Message-Instance")] == [b"2", b"1"]
    assert dkim2hop.stream(sent.fields, BODY, dns=dkim2.dkim2_dns, arriving=False).result().status == "pass"

    # mailman records its changes on top, the fan-out adds its own to
    # mailman's instance, and signs for all three
    out, body = through_mailman(sent.fields)
    copy = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert [f.split(b";")[0].split(b"=")[1] for f in copy.named("Message-Instance")] == [b"3", b"2", b"1"]
    assert [copy.tag("DKIM2-Signature", "i"), copy.tag("DKIM2-Signature", "m")] == ["2", "3"]
    assert copy.value("From") == f"Alice <{WRAPPED}>"
    result = verified(dkim2, copy)
    assert result.status == "pass", result.message


def versions(sent):
    """The m= of each Message-Instance, topmost first."""
    return [f.split(b";")[0].split(b"=")[1].decode() for f in sent.named("Message-Instance")]


def test_unwrapped_to_on_an_unsigned_post_is_recorded_too(dkim2, keys, our_key_only):
    """No chain yet, and we still say what we did: one m=1, with the
    Recipe back to the post as it arrived.  Nobody has signed, so this
    means nothing outside; the list fan-out signs over it."""
    sent = send(dkim2, to_list_and_wrap(keys, signed=False), BODY, AUTHOR, [LIST, WRAP])
    assert sent.value("To") == f"{LIST}, {UNWRAPPED}"
    assert sent.named("DKIM2-Signature") == []
    assert versions(sent) == ["1"]
    assert dkim2hop.stream(sent.fields, BODY, dns=dkim2.dkim2_dns, arriving=False).result().status == "pass"
    # undoing m=1 gives the To that arrived
    recipe = base64.b64decode(sent.tag("Message-Instance", "r")).decode()
    assert WRAP in recipe


def test_with_verification_only_the_chain_is_removed(dkim2, keys, our_key_only, monkeypatch):
    """No key directory at all: nothing is ever signed, so a change is not
    recorded and the chain it would break is removed (test_dkim2_keyless)."""
    monkeypatch.setattr(dkim2, "dkim2_keydir", None)
    sent = send(dkim2, our_key_only, BODY, AUTHOR, [LIST, WRAP])
    assert sent.named("DKIM2-Signature") == []
    assert versions(sent) == []


def test_from_taken_over_for_an_alias_is_recorded(dkim2, keys, monkeypatch):
    """An alias is a local recipient: this transaction relays nothing
    off-site, so nothing is signed here.  The DMARC rule still wraps From,
    and that is recorded."""
    alias = "chair@ietf.org"
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    monkeypatch.setattr(dkim2, "get_db_pool", lambda: harness.FakeDB(virtual=[alias], down=False))
    dkim2._policy_cache.clear()
    sent = send(dkim2, author_post(keys), BODY, AUTHOR, [alias])
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert len(sent.named("DKIM2-Signature")) == 1
    assert versions(sent) == ["2", "1"]
    assert dkim2hop.stream(sent.fields, BODY, dns=dkim2.dkim2_dns, arriving=False).result().status == "pass"


def test_changes_are_recorded_on_a_chain_that_failed(dkim2, keys, our_key_only):
    """The chain was already broken when it arrived.  We do not sign, and
    we still record our own change on top of it."""
    sent = send(dkim2, our_key_only, BODY + b"tampered\r\n", AUTHOR, [LIST, WRAP])
    assert sent.value("X-DKIM2-Arrival") == "fail"
    assert len(sent.named("DKIM2-Signature")) == 1
    assert versions(sent) == ["2", "1"]


# --- list fan-out ---------------------------------------------------------------

def test_footer_means_new_from_and_a_verifiable_chain(dkim2, keys):
    """The body changed since example.com signed, so the copy leaves with a
    From of ours, recorded in mailman's instance, and our signature."""
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)

    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert sent.value("X-Original-From") == f"Alice <{AUTHOR}>"
    assert [sent.tag("Message-Instance", "m"), sent.tag("DKIM2-Signature", "i")] == ["2", "2"]
    assert sent.tag("DKIM2-Signature", "m") == "2"
    assert sent.tag("DKIM2-Signature", "d") == "ietf.org"
    assert sent.tag("DKIM2-Signature", "f") == "exploded"
    # the signature names the envelope the copy actually leaves in
    assert base64.b64decode(sent.tag("DKIM2-Signature", "mf")).decode() == f"<{sent.mail_from}>"
    assert sent.mail_from != BOUNCES
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_body_the_list_could_not_describe_is_still_signed(dkim2, keys):
    """Mailman rewrote the body and recorded only that it did (a null body
    Recipe).  The body is not the one example.com signed and cannot be put
    back, but the copy came to us from our own list manager: it gets a From
    of ours, recorded in mailman's instance, and our signature.  Verifiers
    report a null Recipe as a permerror (-09), which is the truth."""
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived, null_body=True)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert [f.split(b";")[0].split(b"=")[1] for f in sent.named("Message-Instance")] == [b"2", b"1"]
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["2", "2"]
    result = verified(dkim2, sent)
    assert result.status == "permerror" and "m=2 has a null recipe" in result.message


def test_unsigned_post_with_the_lists_instance_is_signed_over_it(dkim2, monkeypatch):
    """Nobody signed the post; mailman's m=1 describes what it handed us.
    The DMARC rule gives the copy a From of ours, recorded in mailman's
    m=1, and i=1 covers it: it is not thrown away."""
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    dkim2._policy_cache.clear()
    plain = fields(("X-DKIM2-Arrival", "none"), ("From", f"Alice <{AUTHOR}>"), ("To", LIST),
                   ("Subject", "hello"))
    out, body = through_mailman(plain)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert [f.split(b";")[0].split(b"=")[1] for f in sent.named("Message-Instance")] == [b"1"]
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["1", "1"]
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_no_footer_keeps_the_authors_from(dkim2, keys):
    """Headers changed, the body did not: example.com still answers for the
    content, so From stays and we only add our signature."""
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived, footer=b"")
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{AUTHOR}>"
    assert sent.mail_from == BOUNCES
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["2", "2"]
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


UNSIGNED = [("X-DKIM2-Arrival", "none"), ("From", f"Alice <{AUTHOR}>"), ("To", LIST),
            ("Subject", "[ietf] hello"), ("List-Id", "<ietf.ietf.org>")]


def test_unsigned_post_keeps_its_from_and_goes_out_unsigned(dkim2):
    """No DKIM2 on the post: that alone is no reason to take From over, and
    a From that is not ours is not ours to sign for."""
    sent = send(dkim2, fields(*UNSIGNED), BODY + FOOTER, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.result == dkim2.Milter.ACCEPT
    assert sent.value("From") == f"Alice <{AUTHOR}>"
    assert sent.named("DKIM2-Signature") == [] and sent.named("Message-Instance") == []
    assert sent.mail_from == BOUNCES


def test_unsigned_post_rewritten_for_dmarc_starts_a_chain(dkim2, monkeypatch):
    """The DMARC rule gives the copy a From of ours, so we can sign it: the
    chain starts here."""
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    dkim2._policy_cache.clear()
    sent = send(dkim2, fields(*UNSIGNED), BODY + FOOTER, BOUNCES,
                [SUBSCRIBER, "other@example.org"], auth=MAILMAN)
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    # one m=1, whose Recipe gives back the post as mailman handed it over
    assert versions(sent) == ["1"]
    assert [sent.tag("DKIM2-Signature", "i"), sent.tag("DKIM2-Signature", "m")] == ["1", "1"]
    # every recipient of the transaction is named together
    rt = [base64.b64decode(x).decode() for x in sent.tag("DKIM2-Signature", "rt").split(",")]
    assert rt == [f"<{SUBSCRIBER}>", "<other@example.org>"]
    result = verified(dkim2, sent)
    assert result.status == "pass", result.message


def test_failed_arrival_is_not_signed_and_from_is_left_alone(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "fail")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.result == dkim2.Milter.ACCEPT
    assert len(sent.named("DKIM2-Signature")) == 1
    assert sent.value("From") == f"Alice <{AUTHOR}>"


def test_changes_nobody_recorded_are_not_signed(dkim2, keys):
    """A list manager that changed the message without a Message-Instance
    (stock Mailman): there is no Recipe for what it did and we cannot write
    one, so the copy goes out as it is -- From and envelope included,
    since we will not be signing to answer for it."""
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived, instance=False)
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.result == dkim2.Milter.ACCEPT
    assert len(sent.named("DKIM2-Signature")) == 1
    assert sent.value("From") == f"Alice <{AUTHOR}>"
    assert sent.named("X-Original-From") == []
    assert sent.mail_from == BOUNCES


def test_list_copy_with_no_offsite_recipient_is_not_signed(dkim2, keys):
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived)
    sent = send(dkim2, out, body, BOUNCES, ["archive@ietf.org"], auth=MAILMAN)
    assert len(sent.named("DKIM2-Signature")) == 1


# --- DKIM2 never stops the mail ----------------------------------------------------

def test_a_broken_key_file_sends_the_copy_unsigned(dkim2, keys, tmp_path, monkeypatch):
    (tmp_path / "ietf.org").mkdir()
    (tmp_path / "ietf.org" / "sel1.key").write_text("this is not a key")
    monkeypatch.setattr(dkim2, "dkim2_keydir", str(tmp_path))
    arrived = fields(("X-DKIM2-Arrival", "pass")) + author_post(keys)
    out, body = through_mailman(arrived, footer=b"")
    sent = send(dkim2, out, body, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.result == dkim2.Milter.ACCEPT
    assert len(sent.named("DKIM2-Signature")) == 1


@pytest.mark.parametrize("where", ["Stream", "feed", "result", "sign"])
def test_an_error_in_dkim2_is_logged_and_the_mail_goes_on(dkim2, keys, monkeypatch, where):
    post = author_post(keys)

    def boom(*a, **kw):
        raise RuntimeError("boom")
    if where == "Stream":
        monkeypatch.setattr(dkim2hop, "Stream", boom)
    elif where == "sign":
        monkeypatch.setattr(dkim2hop, "sign", boom)
    else:
        monkeypatch.setattr(dkim2hop.Stream, where, boom)
    # arriving: delivered, with no verdict we could not reach
    sent = send(dkim2, post, BODY, AUTHOR, [LIST])
    assert sent.result == dkim2.Milter.ACCEPT
    if where != "sign":
        assert sent.named("Authentication-Results") == [] and sent.named("X-DKIM2-Arrival") == []
    # fan-out: sent, unsigned, and the DMARC rewrite still happens
    pins = harness.parse_pins(["example.com=reject"], "--dmarc")
    monkeypatch.setattr(dkim2, "checkdmarc", harness.LoggedCheckdmarc(harness.FakeDNS(pins, {}, True)))
    dkim2._policy_cache.clear()
    sent = send(dkim2, fields(*UNSIGNED), BODY + FOOTER, BOUNCES, [SUBSCRIBER], auth=MAILMAN)
    assert sent.result == dkim2.Milter.ACCEPT
    assert sent.value("From") == f"Alice <{WRAPPED}>"
    assert sent.named("DKIM2-Signature") == []


def test_a_header_field_dkim2_cannot_take_does_not_stop_the_message(dkim2):
    ctx = Ctx({"i": "TEST01", "{auth_authen}": None})
    m = dkim2.EnvelopeMilter()
    m._ctx = ctx
    m.envfrom(f"<{AUTHOR}>")
    m.envrcpt(f"<{LIST}>")
    m.header("From", AUTHOR)
    m.header("X-Odd\u00e9", "value")          # not an ASCII field name
    m.header("To", LIST)
    m.eoh()
    m.body(b"x\r\n")
    assert m.eom() == dkim2.Milter.ACCEPT
    assert m.dkim2_off and ctx.actions == []


# --- what a sender wrote does not become our words ----------------------------------

def test_authentication_results_takes_nothing_unquoted_from_the_message():
    class Result:
        status = "fail"
        message = 'FAIL: DKIM2-Signature i=1\r\n\tInjected: x "quoted" \\ \xff'
        domain = "evil.example dkim2=pass header.d=ietf.org"
    value = dkim2hop.authentication_results(Result, "mail.ietf.org")
    assert value == ('mail.ietf.org; dkim2=fail '
                     'reason="FAIL: DKIM2-Signature i=1 Injected: x \\"quoted\\" \\\\"')
    assert "header.d" not in value and "\n" not in value and "\r" not in value
    Result.domain = "x\r\n dmarc=pass\r\n header.from=ietf.org\r\n y.evil.example"
    assert "dmarc" not in dkim2hop.authentication_results(Result, "mail.ietf.org")
    Result.domain = "Lists.Example.COM"
    assert dkim2hop.authentication_results(Result, "mail.ietf.org").endswith(" header.d=lists.example.com")


def test_hostile_signing_domain_never_reaches_the_report(dkim2, keys):
    hostile = fields(("DKIM2-Signature", "i=1; m=1; t=1740000000; d=evil.example dkim2=pass header.d=ietf.org; "
                                         "mf=PD4=; rt=PD4=; s=sel:ed25519-sha256:QUJD"),
                     ("Message-Instance", "m=1; h=sha256:AAAA:AAAA;"),
                     ("From", AUTHOR), ("To", LIST))
    sent = send(dkim2, hostile, BODY, AUTHOR, [LIST])
    report = sent.value("Authentication-Results")
    assert report.startswith("mail.ietf.org; dkim2=")
    assert "dkim2=pass" not in report and "header.d=ietf.org" not in report


def test_clean():
    assert dkim2hop.clean("a\r\n\tb  c\x00\xe9") == "a b c"
    assert len(dkim2hop.clean("x" * 1000)) == 300


def test_key_lookup_stays_inside_the_key_directory(keys, tmp_path):
    keydir, _dns = keys
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "tls.key").write_text("x")
    for domain in ("../outside", f"{outside}", f"/{outside}", "ietf.org/", "x.ietf.org/../ietf.org",
                   "ietf..org", ".ietf.org", "ietf.org\x00", "ietf.org/../../etc", "a b.ietf.org"):
        assert dkim2hop.find_key(keydir, domain) is None, domain
    for selector in ("../x", "a/b", ".hidden", "sel1/../sel1", ""):
        found = dkim2hop.find_key(keydir, "ietf.org", selector)
        assert found is None or found[1] == "sel1", selector
    assert dkim2hop.find_key(keydir, "sub.dmarc.ietf.org")[0] == "ietf.org"
    assert dkim2hop.find_key(keydir, "xn--bcher-kva.ietf.org")[0] == "ietf.org"


def test_a_message_never_finished_drops_its_lookups(dkim2, keys):
    ctx = Ctx({"i": "TEST01", "{auth_authen}": None})
    m = dkim2.EnvelopeMilter()
    m._ctx = ctx
    dropped = []
    for end in ("abort", "close", "envfrom"):
        m.envfrom(f"<{AUTHOR}>")
        m.envrcpt(f"<{LIST}>")
        for field in author_post(keys):
            name, value = field.split(b":", 1)
            m.header(name.decode(), value.strip().decode())
        m.eoh()
        seen = m.seen
        seen.abandon = lambda end=end: dropped.append(end)
        if end == "envfrom":
            m.envfrom(f"<{AUTHOR}>")          # the next message on the connection
        else:
            assert getattr(m, end)() == dkim2.Milter.CONTINUE
        assert m.seen is None or m.seen is not seen
    assert dropped == ["abort", "close", "envfrom"]


# --- configuration ---------------------------------------------------------------

def test_off_by_default(rewriter, keys):
    assert rewriter.dkim2_keydir == "" and rewriter.dkim2_authserv_id == ""
    monkey_db = harness.FakeDB(virtual=(), down=False)
    rewriter.get_db_pool = lambda: monkey_db
    rewriter.checkdmarc = harness.LoggedCheckdmarc(harness.FakeDNS({}, {}, True))
    sent = send(rewriter, author_post(keys), BODY, AUTHOR, [LIST])
    assert sent.actions == []


def test_selector_newest_key_unless_named(keys, tmp_path):
    keydir, _dns = keys
    assert dkim2hop.find_key(keydir, "ietf.org", "sel1")[1] == "sel1"
    assert dkim2hop.find_key(keydir, "ietf.org", "nosuch") is None
    domain = tmp_path / "ietf.org"
    domain.mkdir()
    assert dkim2hop.find_key(str(tmp_path), "ietf.org") is None
    for name, mtime in (("old", 1000), ("new", 3000), ("middle", 2000)):
        (domain / f"{name}.key").write_text("x")
        os.utime(domain / f"{name}.key", (mtime, mtime))
    (domain / "notes.txt").write_text("not a key")
    assert dkim2hop.find_key(str(tmp_path), "ietf.org")[1] == "new"
    # a named selector wins over the newest
    assert dkim2hop.find_key(str(tmp_path), "ietf.org", "old")[1] == "old"
    # the same time on every file, as in a mounted Secret: last by name
    for name in ("old", "new", "middle"):
        os.utime(domain / f"{name}.key", (5000, 5000))
    assert dkim2hop.find_key(str(tmp_path), "ietf.org")[1] == "old"
