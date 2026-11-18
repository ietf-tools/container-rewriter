"""DKIM2 for the rewriter (draft-ietf-dkim-dkim2-spec-09).

The rewriter is the hop that changes a message's From, To and Cc and its
envelope, so it is the one place that knows both what the message looked
like before and what it will be sent as.  This module turns that into the
things DKIM2 asks of such a hop:

  verify()  on the way in: is the chain of DKIM2-Signature and
            Message-Instance fields the message arrived with intact, and
            does it match the envelope it arrived in?

  sign()    on the way out: a Message-Instance recording what the rewriter
            changed (with a Recipe that puts the old header fields back),
            and a DKIM2-Signature over the envelope the message leaves in.

  record()  when the rewriter changed the message but is not the one to
            sign it: the Message-Instance alone, for a later hop of ours
            to sign over.

Nothing here talks to the milter.  It takes and returns header fields and
bytes, so it can be tested without one; rewriter.py does the wiring.

The body is never held.  A Stream is made from the header fields when they
have all arrived, and fed the body as it comes: it hashes the body and
verifies the chain in the same pass, and verify() and sign() work from that.

The DKIM2 implementation itself is vendored, unchanged, in vendor/dkim2
(see VENDOR.md there).
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "dkim2"))

import dkim2sign  # noqa: E402
import dkim2undo  # noqa: E402
import dkim2verify  # noqa: E402
from dkim2dns import LiveDNS  # noqa: E402

CRLF = b"\r\n"


# a domain name in ASCII (A-labels included): what a signing domain's
# directory may be called, and what header.d may report
_HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
                       r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
_SELECTOR = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9._-]{0,200}[A-Za-z0-9_])?")


def clean(text, limit=300):
    """Text from a message made safe to put in a log line or a header field
    of ours: printable ASCII only, runs of white space as one space, and no
    longer than `limit`.  What a sender wrote must not be able to continue
    a header field onto a new line, or start a new log line."""
    text = "".join(c if " " <= c <= "~" else " " for c in str(text))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _name(field):
    """A header field's name, lower-cased, without white space before the colon."""
    return field.split(b":", 1)[0].strip().lower()


def _path(addr):
    """An envelope address as an RFC 5321 path: in angle brackets, <> if empty."""
    addr = (addr or "").strip()
    if addr.startswith("<") and addr.endswith(">"):
        return addr
    return f"<{addr}>"


def _domain(addr):
    addr = _path(addr)[1:-1]
    return addr.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in addr else ""


def header_field(name, value):
    """One header field as it is on the wire, from the name and value a
    milter is handed (the value's line breaks are bare LFs)."""
    if isinstance(name, str):
        name = name.encode("ascii", "surrogateescape")
    if isinstance(value, str):
        value = value.encode("utf-8", "surrogateescape")
    value = value.replace(b"\r\n", b"\n").replace(b"\n", CRLF)
    return name + b": " + value + CRLF


def find_key(keydir, domain, selector=None):
    """The key to sign with for an envelope sender in `domain`.

    keydir holds one directory per signing domain, with the key for
    selector S in <keydir>/<signing domain>/S.key (PEM).  The signing
    domain has to be the sender's domain or a parent of it (-09 section
    10.8), so the nearest directory wins.  With no selector given, the
    newest key in the directory is used (by modification time; of keys
    with the same time, the last by name), and its file name is the
    selector.
    Returns (signing_domain, selector, path), or None.
    """
    # The domain comes from an envelope address, and the selector may come
    # from configuration: neither may name anything but a directory and a
    # file directly under keydir.
    domain = (domain or "").lower().rstrip(".")
    if not _HOSTNAME.fullmatch(domain) or (selector and not _SELECTOR.fullmatch(selector)):
        return None
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        directory = os.path.join(keydir, candidate)
        if not os.path.isdir(directory):
            continue
        if selector:
            path = os.path.join(directory, f"{selector}.key")
            return (candidate, selector, path) if os.path.isfile(path) else None
        found = [f for f in os.listdir(directory) if f.endswith(".key")]
        if not found:
            return None
        newest = max(found, key=lambda f: (os.stat(os.path.join(directory, f)).st_mtime, f))
        return candidate, newest[:-len(".key")], os.path.join(directory, newest)
    return None


def _bare(header_fields):
    """Header fields as the vendored code takes them: no final line break."""
    return [f[:-2] if f.endswith(CRLF) else f for f in header_fields]


class Stream:
    """One message, seen once: the header fields, then the body in pieces.

    Made when the header fields are complete, with the envelope the message
    arrived in.  feed() takes the body as it comes.  Afterwards result() is
    the verdict on the DKIM2 chain the message arrived with, and
    body_hash() the hash of the body; neither needed the body kept.

    may_sign=False says the message will not be signed whatever happens
    (it has no recipient we relay to, or signing is off).  A message with
    no Message-Instance then has nothing its body is needed for, and the
    body is not hashed.

    arriving=True is mail from outside: the chain must be complete and the
    newest signature must name this envelope (-09 section 14.4).  Otherwise
    the message is one we are about to send on, handed to us by our own
    list manager: a Message-Instance nobody has signed yet is the one our
    signature will cover, and the envelope is not the previous hop's.
    """

    def __init__(self, fields, mail_from=None, rcpt_to=(), dns=None, arriving=True,
                 may_sign=True):
        self.fields = list(fields)
        names = {_name(f) for f in self.fields}
        # The body is only read when something needs it.  A message with no
        # Message-Instance has no body hash to check, so its body is hashed
        # only if we may yet sign it (may_sign: our own m=1 would need the
        # hash); and with no DKIM2 field at all the verdict is "none" from
        # the header fields alone.
        self.hashed = b"message-instance" in names or may_sign
        self._verify_body = bool(names & {b"message-instance", b"dkim2-signature"})
        algs = {"sha256"}
        for field in self.fields:
            if _name(field) == b"message-instance":
                try:
                    sets = dkim2verify.parse_hash_sets(
                        dkim2sign._mi_hashes(field.decode("utf-8", "surrogateescape")))
                    algs.update(alg for alg, _hh, _bh in sets if alg == "sha512")
                except Exception:
                    pass    # the verifier will say what is wrong with it
        self._hasher = dkim2sign.BodyHasher(sorted(algs))
        self._verifier = dkim2verify.MessageVerifier(
            dns if dns is not None else LiveDNS(), full_chain=True,
            mail_from=_path(mail_from) if arriving else None,
            rcpt_to=[_path(r) for r in rcpt_to] if arriving else None,
            allow_unsigned_mi=not arriving)
        self._verifier.feed(b"".join(self.fields) + CRLF)
        self._result = None

    def feed(self, chunk):
        if self.hashed:
            self._hasher.feed(chunk)
        if self._verify_body:
            self._verifier.feed(chunk)

    def result(self):
        """The vendored verifier's result: .status is 'pass', 'fail',
        'permerror', 'temperror' or 'none', .message says why."""
        if self._result is None:
            self._result = self._verifier.close()
        return self._result

    def abandon(self):
        """The message will not be finished: drop its key lookups that have
        not started."""
        self._verifier.abandon()

    def body_hash(self, alg="sha256"):
        """The body's hash, or None if the body was not hashed."""
        return self._hasher.digest(alg) if self.hashed else None

    def body_changed_since_signature(self):
        """Is the body no longer the one the newest DKIM2-Signature covered?

        The newest signature names a Message-Instance (its m=), which holds
        the body hash from when that signature was made.  True when the
        body hashes differently now: somebody since has changed it, and
        whoever sends it on answers for the message, so From has to become
        an address of theirs.  False for a message with no signature (there
        is nothing to have changed since) and for a chain that cannot be
        read.
        """
        signatures = [f.decode("utf-8", "surrogateescape") for f in self.fields
                      if _name(f) == b"dkim2-signature"]
        if not signatures:
            return False
        try:
            top = max(signatures, key=dkim2sign._get_seq_from_sig)
            covered = dkim2sign._get_mi_from_sig(top)
            for field in self.fields:
                if _name(field) != b"message-instance":
                    continue
                text = field.decode("utf-8", "surrogateescape")
                if dkim2sign._get_version_from_mi(text) != covered:
                    continue
                sets = dkim2verify.parse_hash_sets(dkim2sign._mi_hashes(text))
                return not any(
                    body_hash == dkim2sign.b64(self.body_hash(alg))
                    for alg, _header_hash, body_hash in sets if alg in ("sha256", "sha512"))
        except Exception:
            pass
        return False


def stream(fields, body, mail_from=None, rcpt_to=(), dns=None, arriving=True,
           may_sign=True):
    """A Stream that has been fed a body held in one piece (for tests and
    tools; a milter feeds it as the body arrives)."""
    s = Stream(fields, mail_from, rcpt_to, dns, arriving, may_sign)
    s.feed(body)
    return s


def verify(fields, body, mail_from, rcpt_to, dns=None):
    """Verify the DKIM2 chain a message arrived with, given the whole of it.

    fields are the header fields as received, body the body.  mail_from
    and rcpt_to are the envelope it arrived in: the newest signature has
    to name them (-09 section 14.4).  Returns Stream.result().
    """
    return stream(fields, body, mail_from, rcpt_to, dns).result()


def authentication_results(result, authserv_id):
    """An Authentication-Results value for a verify() result.

    The reason and the signing domain come from the message.  The reason is
    reduced to plain text inside a quoted string; the domain is given only
    if it is a domain name, since it stands unquoted, where anything else
    could pass itself off as a further result.
    """
    reason = clean(result.message).replace("\\", "\\\\").replace('"', '\\"')
    value = f"{authserv_id}; dkim2={result.status}"
    if result.status not in ("pass", "none") and reason:
        value += f' reason="{reason}"'
    domain = (result.domain or "").strip()
    if _HOSTNAME.fullmatch(domain):
        value += f" header.d={domain.lower()}"
    return value


class Signed:
    """What sign() decided.

    insert   header fields to put at the top of the message, topmost first,
             as (name, value) with LF line breaks, ready for insheader()
    change   header fields to rewrite in place, as (name, index, value) for
             chgheader() (index counts fields of that name from the top, from 1)
    reason   why nothing was signed, when insert and change are empty
    domain   the signing domain
    """

    def __init__(self, insert=(), reason=None, domain=None, change=()):
        self.insert = list(insert)
        self.change = list(change)
        self.reason = reason
        self.domain = domain

    def __bool__(self):
        return bool(self.insert or self.change)


_BASE64_TAGS = ("r", "s", "h", "mf", "rt")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]{61,}")


def fold(value, width=76):
    """A Message-Instance or DKIM2-Signature value folded for the wire, with
    LF line breaks as a milter wants them.

    Only where the grammar allows white space: after a tag's ";", and inside
    the base64 of r=, s=, h=, mf= and rt=.  The signing input has all white
    space removed (-09 section 12.8), so folding changes no signature.
    """
    lines, line = [], ""
    for tag in [t.strip() for t in value.strip().rstrip(";").split(";")]:
        name = tag.split("=", 1)[0].strip()
        if name in _BASE64_TAGS:
            tag = _BASE64_RUN.sub(
                lambda m: "\n\t".join(m.group(0)[i:i + 60]
                                      for i in range(0, len(m.group(0)), 60)), tag)
        piece = tag + ";"
        first = piece.split("\n", 1)[0]
        if line and len(line) + 1 + len(first) > width:
            lines.append(line)
            line = piece
        else:
            line = f"{line} {piece}" if line else piece
        if "\n" in line:
            *done, line = line.split("\n")
            lines.extend(done)
    if line:
        lines.append(line)
    return "\n\t".join(l.strip() for l in lines)


def _for_milter(field):
    name, value = field.split(b":", 1)
    value = value.strip().replace(CRLF, b"\n").decode("utf-8", "surrogateescape")
    return name.decode("ascii"), fold(value)


def _instances(seen, after):
    """The Message-Instance fields that say what the rewriter changed,
    topmost first; empty if it changed nothing DKIM2 hashes.

    A message that has instances gets the next m=, with a Recipe that
    restores the header fields the rewriter changed.  Every instance
    already there stays, signed or not: one nobody has signed is another
    of our own hops' (the rewriter on arrival, the list manager), handed
    to us over a path we trust.

    A message with none enters DKIM2 here, and gets one: m=1 for the
    message as we send it, with the Recipe back to the message as we were
    handed it (-09 section 12.1: the first instance MAY carry Recipes, and
    one system's changes belong in one instance).
    """
    before = seen.fields
    if (dkim2sign.compute_header_hash(_bare(before))
            == dkim2sign.compute_header_hash(_bare(after))):
        return []
    body_hashes = {"sha256": seen.body_hash("sha256")}
    instances = [f.decode("utf-8", "surrogateescape") for f in after
                 if _name(f) == b"message-instance"]
    version = max((dkim2sign._get_version_from_mi(f) for f in instances), default=0) + 1
    # header fields only: the body is the one we were given
    recipe = dkim2sign.build_recipes(_bare(before), b"", _bare(after), b"")
    mine = dkim2sign.build_message_instance_from_hashes(
        _bare(after), body_hashes, version=version, recipe=recipe)
    return [mine.encode("utf-8") + CRLF]


def _merged(seen, after):
    """The list manager's Message-Instance with the rewriter's changes
    folded in, as (index among the Message-Instance fields from the top,
    field), or None to record them in an instance of our own.

    A list copy is changed twice by the same organisation in the same hop:
    by the list manager, which says so in an instance nobody has signed, and
    by the rewriter (a From of ours).  One instance says it all: the top
    one keeps its m=, gets the hashes of the copy as it leaves, and a
    header Recipe back to the message as the list received it (the list
    manager's Recipe applied first, then the difference worked out again).
    Its body Recipe is the list manager's: the rewriter does not change the
    body.  None when nothing DKIM2 hashes changed, when a signature already
    covers the top instance (it is not ours to rewrite), or when the
    instance cannot be taken apart (a null header Recipe, an algorithm we
    did not hash the body with).
    """
    before = _bare(seen.fields)
    if dkim2sign.compute_header_hash(before) == dkim2sign.compute_header_hash(_bare(after)):
        return None
    instances = [f.decode("utf-8", "surrogateescape") for f in after
                 if _name(f) == b"message-instance"]
    signatures = [f.decode("utf-8", "surrogateescape") for f in after
                  if _name(f) == b"dkim2-signature"]
    if not instances or dkim2sign.chain_range_error(instances, signatures):
        return None
    versions = [dkim2sign._get_version_from_mi(f) for f in instances]
    top = max(versions)
    if any(dkim2sign._get_version_from_mi(f) >= top for f in signatures):
        return None
    field = instances[versions.index(top)]
    try:
        recipe = dkim2undo.decode_recipes(field) or {}
        previous = before
        if "h" in recipe:
            previous = dkim2undo.reconstruct_headers(before, recipe["h"])
        sets = "".join(dkim2sign._extract_tag(field.split(":", 1)[1], "h").split())
        body_hashes = {s.split(":", 1)[0]: seen.body_hash(s.split(":", 1)[0])
                       for s in sets.split(",")}
    except (ValueError, KeyError, AttributeError):
        return None
    merged = dkim2sign.build_recipes(previous, b"", _bare(after), b"") or {}
    if "b" in recipe:
        merged["b"] = recipe["b"]
    mine = dkim2sign.build_message_instance_from_hashes(
        _bare(after), body_hashes, version=top, recipe=merged or None)
    return versions.index(top) + 1, mine.encode("utf-8") + CRLF


def _has_chain(header_fields):
    return any(_name(f) in (b"message-instance", b"dkim2-signature") for f in header_fields)


def record(seen, after, merge=False):
    """Record a change the rewriter is not signing for.

    Whenever the rewriter changes a header field DKIM2 hashes it says so
    in a Message-Instance, whether or not it goes on to sign: with no key
    for the envelope sender, a From that is not ours, a copy that is not
    leaving, or a chain that had already failed.  Unsigned, the instance
    means nothing to a verifier outside -- but the chain would not have
    verified there with the change unrecorded either, and this way the
    message says what we did.  A later hop of ours (the list fan-out)
    signs over it.

    seen, after and merge are sign()'s.  Returns a Signed with the fields
    to insert (or, merging, the list's instance to change), or with .reason
    when there is nothing to record (no hashed header field changed) or no
    way to (the body was not hashed, or the instances on the message are not
    numbered as a chain).
    """
    if not seen.hashed:
        return Signed(reason="the body was not hashed")
    existing = [f.decode("utf-8", "surrogateescape") for f in after]
    numbering = dkim2sign.chain_range_error(
        [f for f in existing if f.lower().startswith("message-instance:")],
        [f for f in existing if f.lower().startswith("dkim2-signature:")])
    if numbering:
        return Signed(reason=clean(numbering))
    merged = _merged(seen, after) if merge else None
    if merged:
        idx, field = merged
        return Signed(change=[("Message-Instance", idx, _for_milter(field)[1])])
    mine = _instances(seen, after)
    if not mine:
        return Signed(reason="no hashed header field changed")
    return Signed(insert=[_for_milter(f) for f in mine])


def sign(seen, after, mail_from, rcpt_to, keydir, exploded=False,
         timestamp=None, selector=None, merge=False):
    """Sign a message the rewriter is sending on.

    seen     the Stream the message came through: its header fields as the
             rewriter received them, the body's hash, and the verdict on
             the chain it arrived with
    after    the header fields as the rewriter is sending them (its From,
             To and Cc changes applied); the body it does not change
    mail_from, rcpt_to
             the envelope the message leaves in, after the rewriter's
             changes; they go into the signature's mf= and rt=
    keydir, selector
             see find_key()
    exploded the message is one of many copies (a list's fan-out)
    merge    the message is a copy our list manager handed us: put the
             rewriter's changes into its unsigned instance (_merged())
             rather than one of our own above it

    The rewriter's header changes are recorded first (_instances()), and
    the signature covers every instance below it, so instances nobody
    signed -- the rewriter's own from the message's arrival, the list
    manager's -- are answered for here: they reached us over a path we
    trust.  They must still describe the message: a chain that does not
    verify is not signed (-09 section 12).  A message with no DKIM2 fields
    gets m=1 and i=1, the m=1 with a Recipe for whatever the rewriter
    changed.

    Returns a Signed.  Nothing is signed (and .reason says why) when there
    is no key for the sender's domain, the sender is null, the existing
    chain does not verify, or From is not in the signing domain.
    """
    if not _domain(mail_from):
        return Signed(reason="null or domainless envelope sender")
    key = find_key(keydir, _domain(mail_from), selector)
    if key is None:
        return Signed(reason=f"no signing key for {_domain(mail_from)}")
    domain, selector, keyfile = key

    if not seen.hashed:
        return Signed(reason="the body was not hashed", domain=domain)
    change = []
    merged = _merged(seen, after) if merge else None
    if merged:
        idx, field = merged
        at = [i for i, f in enumerate(after) if _name(f) == b"message-instance"][idx - 1]
        after = after[:at] + [field] + after[at + 1:]
        change = [("Message-Instance", idx, _for_milter(field)[1])]
        mine = []
    else:
        mine = _instances(seen, after)
    after = mine + after
    body_hashes = {"sha256": seen.body_hash("sha256")}

    try:
        added = dkim2sign.sign_fields(
            _bare(after), body_hashes, selector, domain, keyfile,
            mailfrom=_path(mail_from), rcptto=[_path(r) for r in rcpt_to],
            timestamp=timestamp, upstream=seen.result(), exploded=exploded,
            # with no DKIM2 field on the message we were handed, the only
            # instances are the ones just made: nothing upstream to gate on
            skip_upstream_check=not _has_chain(seen.fields))
    except dkim2sign.SigningRefused as e:
        return Signed(reason=clean(e), domain=domain)
    except (OSError, ValueError) as e:
        # a key file that cannot be read, or is not a key
        return Signed(reason=f"cannot use the signing key {keyfile}: {clean(e)}", domain=domain)

    return Signed(insert=[_for_milter(f.encode("utf-8")) for f in added]
                  + [_for_milter(f) for f in mine],
                  change=change, domain=domain)
