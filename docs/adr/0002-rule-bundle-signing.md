# 2. Rule bundle signing and verification

Date: 2026-10-24
Status: accepted

## Context

Rules decide what tripline reports and blocks. An attacker who can change the rules can switch tripline off. A bundle must therefore be signed, and no single stolen key may be enough to weaken it.

## Decision

- Sign bundles with Ed25519 (`crypto/ed25519`). Use the standard library only.
- The signed payload is the bytes `tripline-bundle-v1\n` followed by one line of JSON. The JSON has these fields in this order: `version`, `created_at`, `effective_at`, `signers`, `rules`.
- Write times as UTC RFC 3339 with second precision. `encoding/json` sorts the keys of each rule mapping, so YAML key order and formatting do not change the payload. Signatures are not part of the payload.
- A change to the payload format needs a new prefix, for example `tripline-bundle-v2\n`.
- The trust file lists `keys` (`key_id`, base64 `public_key`, `owner`), `required_signatures` (default 2) and `loosening_delay` (default 24h, minimum 1h).
- Count only distinct `key_id` values that are in the trust file and have a valid signature. A repeated signer counts once.
- Reject a bundle with these typed reasons: `malformed`, `insufficient_signatures`, `invalid_time`, `rollback`, `floor_weakened`, `early_loosening`.
- Reject rollback: `version` must be greater than the applied version.
- Classify each change against the applied bundle as tighten or loosen (see `bundle.Diff`). A removed rule, `enforce` to `monitor`, a lower severity, a wider `X_not_in` allowlist, a shorter `X_in` deny list, a longer `correlate.within` and a removed `on_match` action are loosening. Any other change to `match`, `applies_to` or `correlate` is loosening, because it cannot be shown to be tighter.
- Loosening needs `effective_at - created_at` of at least `loosening_delay`. Tightening may take effect at once. A valid bundle with `effective_at` after now is returned as pending.
- Floor rules are compiled into the binary (`internal/floor`). A bundle rule that reuses a floor ID may only raise severity or mode. Its match must stay the same. A bundle that drops a floor rule that the applied bundle had is also rejected.
- Every outcome, accepted or rejected, is returned as a `bundle.Outcome` that the watcher records as an audit event. It holds the reason and the changes. It holds no signature or rule content.

## Consequences

- An attacker needs `required_signatures` private keys to change the rules, and then must wait for the loosening delay while the watcher alerts.
- Stolen keys can still tighten rules at once. This is accepted: tightening does not hide an attack.
- The trust file is the root of trust. Operators must keep it root-owned and read-only to tripline.
- Conservative classification can delay a harmless change. It never lets a loosening change skip the delay.
- `path.Match` globs do not cross `/`. The credential-file floor rule lists common home layouts. This is a known limit.
