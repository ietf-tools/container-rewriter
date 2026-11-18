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
- records the header fields the rewriter itself changed in a
  `Message-Instance`, with a Recipe that restores them (below); a message
  it did not change, with no `Message-Instance`, gets `m=1`;
- adds a `DKIM2-Signature` naming the envelope the message leaves in. It
  covers every instance below it, so one signature answers for mailman's
  unsigned instance and the rewriter's own (see "The trusted path"). Every
  recipient of the SMTP transaction goes into `rt=` together, so whatever
  batches the recipients decides who is named alongside whom;
- sets the `exploded` flag on a mailman fan-out.

It does not sign, and logs why, when: there is no key for the envelope
sender's domain; the envelope sender is null (bounces); the chain already on
the message does not verify; or From is not in the signing domain.

**Whenever it changes a hashed header field**, signing or not, with either
setting on, the rewriter says so in `Message-Instance` fields. Its header
changes apply to every copy of a message, including ones it will not sign:
To and Cc are shown unwrapped on a reply to a wrapped address whether or
not anything makes it take the envelope over; From is wrapped for an alias,
which is a local recipient; the chain may have failed on arrival. In each
case the change is recorded:

- a message that has `Message-Instance` fields gets the next one, with the
  Recipe that undoes the change;
- a message with none enters DKIM2 here and gets a single `m=1` for the
  message as it leaves, with the Recipe back to the message as it was handed
  over (-09 section 12.1 lets the first instance carry Recipes, and one
  system's changes belong in one instance). A forward we sign is `m=1` with
  `i=1; m=1`;
- a list's fan-out (below) gets no instance of its own: the change goes
  into mailman's.

When the rewriter signs, its signature covers them. When it does not, they
stay on the message unsigned. The copy delivered to mailman then has a
chain that describes it, and the fan-out signs over those instances along
with mailman's and its own. A copy that leaves us with unsigned instances
(the reply forwarded to the unwrapped address) will not verify at the next
hop. It would not have with the change unrecorded either, and this way the
message says what was done to it.

**With no key directory at all** (`DKIM2_KEYDIR` unset), nothing the
rewriter sends on will ever be signed, so nothing is recorded. A message it
relays off-site, or whose hashed header fields it changes, has every
`DKIM2-Signature` and `Message-Instance` field removed instead, and is
logged as `dkim2: no signing keys, removed N DKIM2 header fields`. It
leaves with no DKIM2 chain at all (NONE at the next hop) rather than one
that fails (draft-ietf-dkim-dkim2-spec-09 sections 13.1 and 14.2). The
signing pass does the same to every copy. A message delivered unchanged to
a local list keeps its chain for mailman.

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
already is for a sender with a DMARC `reject` or `quarantine` policy, in two
more cases when signing is on:

- **nobody signed the post with DKIM2**, and mailman recorded its
  `Message-Instance` (`dkim2_message_instance` on). The copy starts the
  chain, and we can only sign for a From in our own domain;
- **the post changed since the last DKIM2 signature**, by the list or by
  the rewriter on arrival: its hashed header fields (a subject tag, `List-*`
  fields, an unwrapped To) or its body (a footer) no longer hash as they did
  in the instance that signature covers.

Whoever sends a changed message on answers for it, and under DKIM2 that is
expressed by From. This is the decision the mailman fork makes itself
(`_dkim2_rewrites_from`) on a list with `dkim2_message_instance` on, unless
its `dmarc_mitigate_action` is `defer_to_mta`; with that setting mailman
leaves From to the rewriter, which decides the same way. It does not depend
on the author's DMARC policy or on `DKIM1_MUNGE_FROM`. In practice almost
every list copy we can sign gets a From of ours, since mailman adds hashed
`List-*` fields; a post handed back unchanged keeps the author's From.

The rule applies to mailman fan-out only. Alias forwarding keeps its existing
rules. With `DKIM1_MUNGE_FROM=no` this rule is the only one that rewrites
From.

The From is only taken over when the copy will be signed: if the chain
mailman hands back does not verify as `pass` (stock Mailman, below, or a list
with `dkim2_message_instance` off, whose unsigned post carries no instance),
From and the envelope are left as they are.

## The trusted path

Between the arrival check and the signature the message is in our hands:
the rewriter verified it as it came in, mailman received it from us, and
mailman hands the copies back over an authenticated connection. So when
the arrival verdict was `pass` or `none`, the `Message-Instance` fields
nobody has signed yet are ours to answer for, whichever of our components
wrote them: the rewriter on arrival (above), or mailman. The rewriter keeps
them and signs once over all of them.

On a list's fan-out (mailman's SASL user, a `-bounces` envelope sender),
mailman's top instance and the rewriter's changes to the same copy are one
step by one organisation, so they share one instance. The rewriter rewrites
mailman's unsigned top `Message-Instance` in place: it keeps its `m=`, gets
the hashes of the copy as it leaves, and gets a single header Recipe back to
the message as the list received it (mailman's Recipe applied first, then
the difference worked out again). The body Recipe stays mailman's, since the
rewriter does not change the body. A post signed by its author and given
`m=2` by the list leaves with `m=2` and `i=2; m=2`; a post nobody signed,
which mailman gave an `m=1`, leaves with that `m=1` and `i=1; m=1`. In
split-then-sign mode the first pass rewrites the instance, and the signing
pass signs it. The rewriter adds an instance of its own as before when the
mail is not a fan-out, when a signature already covers the top instance, or
when that instance cannot be taken apart (a null header Recipe, a body hash
algorithm the rewriter did not compute).

The body may have changed since the last signature; that is what the
instances are for. If mailman could not describe the change (it records a
null body Recipe when it rewrites the body), the copy is still signed: From
is ours by then. Verifiers report a null Recipe as `permerror`, as -09 says
they must.

Trust does not replace the Recipes. The instances still have to describe
the message the rewriter was handed, or what we sign would not verify
anywhere.

## What mailman has to do

The rewriter can account for its own changes, not mailman's. If mailman
changes a signed post (subject tag, `List-*` fields, footer) without adding a
`Message-Instance` that says so, there is nothing to undo those changes
with, the chain no longer verifies, and the rewriter leaves the copy as
mailman made it: unsigned, with the author's From. That is safe, and it is
what happens with stock Mailman 3.

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
| `DKIM2_SIGN_DAEMON` | Split then sign. Mail is signed only on connections whose `{daemon_name}` macro equals this; everything else is rewritten and recorded, never signed. Unset, mail is signed in the transaction that relays it off-site. See below. |
| `DKIM1_MUNGE_FROM` | On by default: From is rewritten for a sender whose domain publishes DMARC `p=reject` or `p=quarantine`. `no` turns that off, so From is rewritten only by the From rule (above), on a list fan-out: there, with a signing key, a post nobody signed with DKIM2 or one the list changed still gets a From of ours, as long as mailman recorded its `Message-Instance`. What then keeps the author's From is alias forwards, and list copies whose chain does not verify or carries no instance from the list (stock Mailman, `dkim2_message_instance` off); those may fail DMARC at receivers that do not understand DKIM2. Helm: `rewriter.dkim1MungeFrom: false`. |
| `LIST_VERP` | With `DKIM2_SIGN_DAEMON`: the signing pass gives each list copy mailman's VERP envelope sender, `<list>-bounces+<local>=<domain>@`, so a bounce names the subscriber. `yes` to turn on. See below. |

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

### Split then sign

A signature names every envelope recipient of its transaction (`rt=`), and
the milter sees recipients before Postfix expands aliases. With
`DKIM2_SIGN_DAEMON` set, signing moves to a second pass after expansion:
Postfix sends each off-site copy, one recipient per transaction, to a
loopback listener with `-o milter_macro_daemon_name=<DKIM2_SIGN_DAEMON>`
and this milter, and on to the relay by `content_filter`
(`docs/superpowers/specs/2026-11-15-dkim2-split-then-sign-design.md`).

- **Every other listener** verifies, rewrites and records as above, and
  never signs. A list fan-out gets `X-DKIM2-Exploded: yes`.
- **The signing listener** changes nothing but this: it signs over the
  chain as received (`X-DKIM2-Arrival` says how it arrived; a failed
  arrival is not signed), with `f=exploded` when `X-DKIM2-Exploded` is
  there, and removes `X-DKIM2-Exploded`. No address rewriting, DNS policy
  lookups or database queries.

With `LIST_VERP` on, the signing listener also changes a list's
`-bounces` envelope sender (wrapped by the DMARC rule or not) to mailman's
VERP form for the copy's one recipient, before signing for it:
`ietf-bounces@ietf.org` becomes `ietf-bounces+sub=example.net@ietf.org`,
and `ietf-bounces=40ietf.org@dmarc.ietf.org` becomes
`ietf-bounces+sub=example.net=40ietf.org@dmarc.ietf.org`. Only our own
lists: the list's domain must be in `LOCAL_DOMAINS` (and a wrap's domain in
`REWRITE_DOMAINS`), so another organisation's list post forwarded through
one of our aliases keeps its sender. Recipients that
mailman's `verp_regexp` would not read back (an `=` in the local part, a
quoted or non-ASCII address) keep the plain sender. A bounce to a wrapped
list address is unwrapped in `To:` and `Cc:` as well as in the envelope,
since mailman reads the VERP address from `To:`.

Only the Postfix pods may reach the milter port: the mode is a claim made by
the milter client (`rewriter.networkPolicy` in the chart). Turn it on in
the rewriter before Postfix sends the second pass, and off after: then no
copy is ever signed twice.

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
`Message-Instance` that will not be relayed off-site and is not for an
alias (ordinary mail arriving for a list) is not hashed at all: the
rewriter does not change it, so nothing needs its body. Telling an alias
from a list is one more database lookup, when the header fields have
arrived, for mail with no off-site recipient. Memory per transaction is the
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
   be `none` until senders sign. From this step on, a message whose To, Cc
   or From the rewriter changes gets `Message-Instance` fields saying so.
3. Publish the key record, mount the key, set `DKIM2_KEYDIR` and
   `DKIM2_SELECTOR`. Watch for `dkim2: signed d=…` and `dkim2: not signing:
   <reason>`.
4. Send a signed copy to <https://dkim2.com/validate/> or to
   `reflector-raw@dkim2.com` to check it from outside.

Log lines all start `<queue id> dkim2:`.

## Limits

- Bounces (null envelope sender) are not signed.
- Stock Mailman's list copies of signed posts are not signed, and keep the
  author's From (above).
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
