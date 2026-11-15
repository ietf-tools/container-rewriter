# Vendored DKIM2 implementation

These files are a copy. Do not fix bugs here.

    repository:  https://github.com/dkim2wg/interop
    path:        python/
    commit:      7cbf9b9, copied 2026-11-14
    implements:  draft-ietf-dkim-dkim2-spec-09

    dkim2sign.py    Message-Instance and DKIM2-Signature construction, signing
    dkim2verify.py  chain verification
    dkim2undo.py    Recipe decoding (used by the verifier)
    dkim2plan.py    one-pass hashing of earlier instances (used by the verifier)
    dkim2dns.py     key and policy lookups (dnspython)
    dkim2domain.py  relaxed domain match, From parsing

They need only `cryptography` and `dnspython`, both already in
requirements.txt. dkim2hop.py, next to rewriter.py, is the only code here
that calls them. To refresh, copy the six files again and update the commit
line; behaviour changes go upstream first, where they are tested against
the other DKIM2 implementations.
