# DKIM2 in the rewriter

The rewriter can verify DKIM2 on mail arriving from outside and sign mail it
relays off-site. Both are off unless configured; with nothing set it behaves
exactly as it did before. This implements
[draft-ietf-dkim-dkim2-spec-09](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/).

## Why it lives here

DKIM2 has every hop that changes a message record what it changed, and sign
the envelope the message leaves in. The rewriter is the last thing on the way
out that changes the message (From, To, Cc), and the only component that
knows the final envelope sender and recipients: it sets them. A separate
signing milter would be told the envelope before the rewriter changed it, and
would sign the wrong one. So the rewriter does the signing itself, and no
extra milter is needed in either direction.

## What it does

**On arrival** (a connection that has not authenticated), when
`DKIM2_AUTHSERV_ID` is set:

- verifies the chain of `DKIM2-Signature` and `Message-Instance` fields the
  message came with, against the envelope it came in;
- adds `Authentication-Results: <DKIM2_AUTHSERV_ID>; dkim2=<result>`, with
  the reason when the result is not `pass` or `none`;
- adds `X-DKIM2-Arrival: <result>`, so the verdict is still on the message
  when mailman hands the copies back. One that arrives from outside is
  removed first.

Nothing is rejected. A message whose chain did not verify is delivered as
usual; it is just not signed later.

**On the way out** (any recipient relayed off-site), when `DKIM2_KEYDIR` is
set:

- does nothing if the arrival verdict was `fail`, `permerror` or
  `temperror`;
- adds a `Message-Instance` recording the header fields the rewriter itself
  changed, with a Recipe that restores them, if the message already has a
  DKIM2 chain; or `m=1` if it has none;
- adds a `DKIM2-Signature` naming the envelope the message leaves in. Every
  recipient of the SMTP transaction goes into `rt=` together, so whatever
  batches the recipients decides who is named alongside whom;
- sets the `exploded` flag on a mailman fan-out.

It does not sign, and logs why, when: there is no key for the envelope
sender's domain; the envelope sender is null (bounces); the chain already on
the message does not verify; or From is not in the signing domain.

## What it relies on

- **Forged local senders are refused before the rewriter sees them.** The
  rewriter signs any message it relays off-site whose envelope sender is in
  a domain it has a key for and whose From is in that domain; it does not
  ask whether the client authenticated. A message from outside claiming an
  envelope sender and From in one of your own domains, sent to an alias or
  a wrapped address that forwards off-site, would be signed as yours. The
  inbound filtering (rspamd) has to reject such mail, as it does today. If
  that ever changes, signing must be limited to authenticated clients
  first.
- **An authenticated client is trusted with From.** Any SASL user who may
  send with an envelope sender in a signing domain gets that domain's
  signature on whatever From in the domain they write.
- **`rt=` names every recipient of the transaction, Bcc included.** A
  client that puts a Bcc recipient in the same SMTP transaction as the
  others discloses that address, base64-encoded, in the signature every
  recipient gets. Whatever submits mail has to send blind copies in
  transactions of their own; Postfix does not do that by itself.

DKIM2 never stops mail. If anything in it fails unexpectedly (a key file
that is not a key, no resolver, a bug), the error is logged as `dkim2: error
in <step>, carrying on without DKIM2` and that message is handled exactly
as if DKIM2 were not configured: no verdict, no signature.

## The From rule

A list copy's From is rewritten to `user=40domain@<FORWARDING_DOMAIN>`, as it
already is for a sender with a DMARC `reject` or `quarantine` policy, in one
more case when signing is on: **the body is no longer the one the last DKIM2
signature covered.** A footer is the usual cause. Whoever sends a changed
body on answers for the message, and under DKIM2 that is expressed by From.

A post with no DKIM2 signature is not rewritten for that reason alone. Its
From stays the author's, and since that From is not in our domain the copy
goes out without our signature, as today. If the DMARC rule rewrites it, it
is signed, and the chain starts with us.

The rule applies to mailman fan-out only. Alias forwarding keeps its existing
rules.

## What mailman has to do

The rewriter can account for its own changes, not mailman's. If mailman
changes a signed post (subject tag, `List-*` fields, footer) without adding a
`Message-Instance` that says so, the chain no longer verifies and the
rewriter leaves the copy unsigned. That is safe, and it is what happens with
stock Mailman 3.

For signed list mail, mailman needs the Message-Instance patches from
<https://github.com/brong/mailman> (branch `dkim2-3.3.10` for the 3.3.10
release; `mailman/README.md` in <https://github.com/dkim2wg/interop> describes
them). With those, set `[mta] message_instance: yes`. Mailman then records
its changes and the rewriter signs over them.

`X-DKIM2-Arrival` must survive mailman, which it does: mailman passes
unknown `X-` fields through.

## Configuration

| Variable | Meaning |
|---|---|
| `DKIM2_AUTHSERV_ID` | Turns on verification of arriving mail, and is the name the result is reported under. See below. |
| `DKIM2_KEYDIR` | Turns on signing. A directory with one sub-directory per signing domain. |
| `DKIM2_SELECTOR` | The selector to sign with: the key is `<DKIM2_KEYDIR>/<signing domain>/<DKIM2_SELECTOR>.key`. If unset, the newest `.key` file in the domain's directory is used, and its name is the selector. See below. |

`DKIM2_AUTHSERV_ID` is the *authserv-id* of RFC 8601: the first thing in an
`Authentication-Results` field, naming the system that did the checking.

```
Authentication-Results: mail.ietf.org; dkim2=pass header.d=example.com
                        ^^^^^^^^^^^^^ DKIM2_AUTHSERV_ID
```

Set it to the name this mail system already reports its checks under: look
at the `Authentication-Results` field on any message that has come through
it (rspamd adds one), and use the same name. It is normally a hostname or
domain you control, such as `mail.ietf.org`. Whatever reads these fields
later decides which to believe by this name, so one that differs from the
other milters' gets the DKIM2 result ignored. Use a plain host or domain
name: the value goes into the field as given, and a space or a semicolon
in it would break the field. Leaving the variable unset turns verification
off.

The signing domain is the envelope sender's domain or its nearest parent
that has a directory. A key in `ietf.org/` therefore signs for
`ietf.org` and for `dmarc.ietf.org`.

### Keys

```sh
mkdir -p keys/ietf.org
openssl genpkey -algorithm ed25519 -out keys/ietf.org/dkim2a.key
# the DNS record's p= value:
openssl pkey -in keys/ietf.org/dkim2a.key -pubout -outform DER | tail -c 32 | base64
```

Publish it where a DKIM key goes; DKIM2 uses the same records:

```
dkim2a._domainkey.ietf.org.  TXT  "v=DKIM1; k=ed25519; p=<the value above>"
```

RSA works too (`openssl genrsa -out … 2048`; `p=` is the base64 of
`openssl rsa -in … -pubout -outform DER`). Keys under 1024 bits are refused
by every verifier.

With `DKIM2_SELECTOR` unset, "newest" is by the file's modification time.
Files mounted from a Kubernetes Secret all carry the same time (that of the
last update to the Secret), so there the last by name wins: name selectors
so that they sort in order (`dkim2-2026a`, `dkim2-2026b`), or set
`DKIM2_SELECTOR`.

To rotate: publish the new selector's record, add the new key file (and
change `DKIM2_SELECTOR` if it is set), restart. Keep the old record
published for two weeks, the longest a signature is accepted for.

### Helm

The chart does not pass these yet. It needs the three variables under `env:`
in `templates/deployment.yaml`, and the key directory mounted read-only from
a Secret, for example:

```yaml
            - name: DKIM2_AUTHSERV_ID
              value: {{ .Values.rewriter.dkim2.authservId | quote }}
            - name: DKIM2_KEYDIR
              value: /etc/dkim2/keys
            - name: DKIM2_SELECTOR
              value: {{ .Values.rewriter.dkim2.selector | quote }}
          volumeMounts:
            - name: dkim2-keys
              mountPath: /etc/dkim2/keys/ietf.org
              readOnly: true
      volumes:
        - name: dkim2-keys
          secret:
            secretName: {{ .Values.rewriter.dkim2.existingSecretName }}
```

with the Secret holding one item named `<selector>.key`.

## Where the rewriter sits among the other milters

- **Arriving mail:** before any milter that changes a header field DKIM2
  hashes, or the body. Adding `X-*`, `Received`, `Authentication-Results`,
  `DKIM-Signature` or `ARC-*` fields is harmless: DKIM2 does not hash them.
  A milter that tags the Subject, say, has to come after.
- **Mail going out:** after any milter that changes a hashed header field or
  the body. The rewriter's signature covers the message as it stands when
  the rewriter runs.

### What it costs

With DKIM2 configured the rewriter is sent the message body, which it was
not before. It does not keep it: the body is hashed, and the chain it
arrived with verified, as each piece comes in. A message with no
`Message-Instance` that will not be relayed off-site (ordinary mail arriving
for a list) is not hashed at all: nothing needs its body. Memory per transaction is the
header fields plus about 130 KB of working space, whatever the size of the
message. CPU is one pass over the body: on a 2026 laptop core, about 3 ms
per megabyte, plus under a millisecond to verify one signature or to sign.

Not in those figures: verifying a chain looks up one key record in the DNS
for each signature on the message, inside the transaction. The lookups
start when the header fields have arrived and overlap the body's arrival.
A message can name hundreds of keys under nameservers that never answer, so
the waiting is capped: after 20 seconds of it for one message, that
message's remaining lookups fail at once and its verdict is `temperror`.

Signing happens once per outgoing SMTP transaction, so a list that sends
one transaction per subscriber pays for it once per subscriber.

With DKIM2 not configured the rewriter asks Postfix not to send the body
at all (pymilter's `nocallback`), as before.

## Rolling it out

1. Deploy with nothing set. Nothing changes.
2. Set `DKIM2_AUTHSERV_ID`. Watch the log for `dkim2: arrival <result>` and
   check `Authentication-Results` on delivered mail. Almost everything will
   be `none` until senders sign.
3. Publish the key record, mount the key, set `DKIM2_KEYDIR` and
   `DKIM2_SELECTOR`. Watch for `dkim2: signed d=…` and `dkim2: not signing:
   <reason>`.
4. Send a signed copy to <https://dkim2.com/validate/> or to
   `reflector-raw@dkim2.com` to check it from outside.

Log lines all start `<queue id> dkim2:`.

## Limits

- Bounces (null envelope sender) are not signed.
- Stock Mailman's list copies of signed posts are not signed (above).
- Signing uses one key. Two signatures side by side (RSA and Ed25519) are
  not supported.
- Postfix's `lmtp_generic_maps` restores the original From on the copy
  delivered to mailman, after every milter has run. If that leaves the From
  field different from the one that arrived, a signed post's chain no longer
  matches by the time mailman sees it, and its list copies go out unsigned.
- Not yet run against a real Postfix. The tests drive the milter class
  through the harness's fake context. Three things are assumed about
  pymilter and Postfix and should be checked on a test instance first: that
  `header()` is shown fields added by milters earlier in the chain; that
  `addheader(name, value, 0)` inserts at the top; that
  `chgheader(name, idx, None)` deletes; and that marking `eoh` and `body`
  with `Milter.nocallback` stops Postfix sending the body when DKIM2 is
  off.

## The code

- `dkim2hop.py` — everything DKIM2 the rewriter needs, with no milter in it.
  A `Stream` is made from the header fields and fed the body as it arrives;
  it gives the verdict on the chain, the body's hash, and whether the body
  changed since the last signature. `sign()` works from a `Stream`;
  `find_key()` picks the key.
- `vendor/dkim2/` — the DKIM2 implementation, copied unchanged from
  <https://github.com/dkim2wg/interop> (`python/`); see `VENDOR.md` there for
  the commit and how to refresh it. It needs only `cryptography` and
  `dnspython`, which `requirements.txt` already has.
- `rewriter.py` — collects the header fields, starts a `Stream` at the end
  of the headers (`eoh()`), feeds it from `body()`, and in `eom()` reports
  the verdict, applies the From rule in the fan-out branch, and signs.
- `tests/test_dkim2hop.py`, `tests/test_dkim2_milter.py` — run with
  `pytest`, like the rest.
