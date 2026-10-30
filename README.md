# sign-safe

A standalone, stdlib-only Python 3.11+ package for inspecting a payload before an
agent signs it. No network requests, wallet access, signing, or runtime dependencies.
Experimental v0.1.0; see [ROADMAP.md](ROADMAP.md) for completed and open work,
[SECURITY.md](SECURITY.md) for the integration boundary, and [LICENSE](LICENSE).

From this source directory (Python 3.11+):

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/sign-safe explain --type permit2 \
  --payload sign_safe/fixtures/payload.json \
  --policy sign_safe/fixtures/policy.yaml --now 1999999900
.venv/bin/python -m pip install pytest
.venv/bin/python -m pytest -q
```

The example returns ALLOW (exit 0) using synthetic addresses and a fixed test time.
Use trusted current time in an integration. `python -m sign_safe` also works in the
installed environment. Installation/test tooling may download packages; runtime
inspection is offline. `requirements.txt` has no runtime requirements.

The CLI emits one sorted-key JSON object containing `decoded`, `verdict`, `reasons`,
and a single loggable `summary`. Exit codes: ALLOW=0, DENY=2, CONFIRM=3. CLI argument
usage errors use argparse's usual stderr/exit 2. Invalid payloads become DENY with
`INVALID_PAYLOAD`; file/configuration errors become `INVALID_INPUT`. The Python API
raises `ValueError` for invalid policy configuration so the integration can fail closed.

## Agent integration (10 lines)

`agent`, `sign`, `audit_log`, and `request_human_review` below are framework adapters.
The review queue must not automatically sign a CONFIRM result. Pass the identical
payload and domain to the signer; prevent mutation between inspection and signing.

```python
from sign_safe import explain, dumps
policy = {"known_spenders": [trusted_spender], "allowed_chain_ids": [1]}
for job in agent.pending_signatures():
    result = explain(job.payload, type=job.type, policy=policy, now=job.trusted_now)
    audit_log(result["summary"], dumps(result))
    if result["verdict"] == "DENY":
        continue
    if result["verdict"] == "CONFIRM":
        request_human_review(job, result); continue
    sign(job.payload)
```

## Inputs and decoding

`decode(payload, type)` returns a normalized dictionary. `explain(payload, *, type,
policy=None, now=None)` decodes, evaluates policy, and returns the structured result.
`PolicyEngine(rules).evaluate(decoded, now=...)` also works separately; feed it only
unaltered decoder output. `dumps(result)` produces canonical sorted-key JSON.
Decoders accept dictionaries or UTF-8 JSON strings/bytes, except raw calldata, which
accepts bytes, hex strings, or transaction dictionaries. CLI files always contain JSON.
All amounts are **raw integer token units**, never guessed symbols or decimal values.

| Type | Accepted payload | Meaning |
| --- | --- | --- |
| `eip7702` | Dictionary with `chain_id, address, nonce, y_parity, r, s`, or six-element list in that order | Installs persistent execution delegation; zero address clears it; chain 0 applies to any chain |
| `eip2612` | `owner, spender, value, nonce, deadline` plus `token`; or an EIP-712 envelope with `domain.verifyingContract` and `message` | Grants allowance; deadline limits submission, **not allowance lifetime** |
| `permit2` | `primaryType` (or `kind`), optional EIP-712 `domain` and `message` | Supports `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom` |
| `raw_calldata` | Hex/bytes or `{data, to?, value?}` | 112 common ERC-20/721/1155/4626, DEX, lending, proxy, access-control and staking selector hints |

**7702 list convention:** six-element lists use the canonical EIP-7702 order
`[chain_id, address, nonce, y_parity, r, s]`. Unsigned intents may use the three-element
list `[chain_id, address, nonce]` or a dictionary with those fields. This library
does not decode RLP, validate signatures, or recover the authorizing EOA.

Permit2 allowance messages contain `details` (object for Single, list for Batch),
`spender`, and `sigDeadline`. Each detail contains `token, amount, expiration, nonce`.
Amounts are uint160; expiration and nonce are uint48. Expiration 0 means the
submission block timestamp, not infinity.

Permit2 signature-transfer messages contain `permitted` (object or list), `spender`,
`nonce`, and `deadline`. Each permission has `token, amount` (uint256). Optional
outer `transferDetails` contains `to, requestedAmount` (object or matching list).
These are **unsigned execution context**, not recipient restrictions. The signed
spender may choose a recipient. Witness types are rejected pending dedicated support.
Missing permit submission deadlines are represented as null and denied by policy.
See `sign_safe/fixtures/` for complete synthetic examples and expected decodes.

Raw calldata decodes static arguments for `approve`, `transfer`, `transferFrom`,
and `setApprovalForAll`; other selectors remain hints. Selector collisions, token
standard ambiguities, proxies, and nested multicalls prevent proving semantics.
Every raw call requires confirmation, even with a known selector. Approval hazards
can additionally yield DENY. Native `value` is reported in wei, not inferred.

## Policy guide

Rules are a plain dict, JSON, or the documented **flat YAML subset** accepted by
`load_policy(text)`. No PyYAML needed. YAML supports top-level keys with JSON scalar
or inline-list values, single-quoted strings, full-line comments, and two-space
indented `- value` lists. Quote addresses. Nested mappings, anchors, aliases,
inline comments, and arbitrary YAML tags are unsupported. Unknown rules and wrong
types fail closed rather than being ignored.

| Rule | Default | Effect |
| --- | --- | --- |
| `known_targets` | `[]` | Only these addresses may receive code delegation |
| `known_spenders` | `[]` | Unknown spenders require CONFIRM; unlimited grants to them are DENY |
| `denied_addresses` | `[]` | DENY on recognized target, owner, spender, token, verifier, or static call address |
| `allowed_chain_ids` | `[]` | If nonempty, deny missing or unlisted chain context |
| `allow_any_chain` | `false` | DENY chain-zero 7702 authorization unless explicitly enabled |
| `max_deadline` | `4102444800` | Absolute submission/Permit2 expiration ceiling (2100-01-01 UTC) |
| `max_validity_seconds` | `2592000` | 30-day relative cap when trusted `now` is supplied |
| `max_amount` | `null` | Optional per-permission raw-unit cap, also applied to decoded static amounts |
| `confirm_unknown_spenders` | `true` | Require review for bounded unknown-spender permissions |

DENY overrides CONFIRM, which overrides ALLOW. Reasons have stable `code`, `message`,
and `verdict` fields and are sorted and deduplicated. Allowlists cannot override
explicit denies, deadline caps, amount limits, or unbound-recipient confirmation.
The engine copies rules and never mutates inputs. Amount caps are per item, not an
aggregate budget; units differ by token.

Defaults reject unknown delegation because it hands over account execution, unlimited
unknown-spender permissions because exposure is unbounded, and missing/max-uint or
above-cap deadlines because there is no acceptable submission window. Trusted
spenders may receive unlimited allowances; set `max_amount` to prohibit these too.
For ERC-2612, perpetual allowance is intrinsic and disclosed, even for bounded amounts.

The library never reads the wall clock. **Always supply trusted `now` in production**
to detect expired permits and enforce the 30-day window; absent `now`, only the
absolute ceiling applies. Deadline equality is accepted. Tighten the absolute ceiling,
chain allowlist, and amount cap for your application. Allowlists are address-based;
use separate engine instances per chain when trust differs across chains.

## Prior art and positioning

Programmatic signing policies exist — sign-safe's difference is being offline, stdlib-only, and keyless, sitting between an agent's decision and its signer:

- [sign-safe-skill](https://github.com/lrafasouza/sign-safe-skill) — an existing offline Solana signing gate with a `sign-safe` CLI; this is a naming collision to resolve before public release.
- [Clef](https://geth.ethereum.org/docs/tools/clef/rules) (Go Ethereum) — external signer with rule-based attestations; a local signer-guardian, not an embeddable Python library.
- [Coinbase CDP policy engine](https://docs.cdp.coinbase.com/api-reference/v2/rest-api/policy-engine/update-a-policy) and [Turnkey policies](https://docs.turnkey.com/features/policies/language) — hosted signer-side policy engines; Turnkey's rules can match EIP-712 and EIP-7702 fields. Powerful, but bound to their custody infrastructure.
- [Uniswap permit2-sdk](https://github.com/Uniswap/sdks/tree/main/sdks/permit2-sdk) — constructs, validates and hashes permit data; a builder/validator, not a configurable signing-policy engine.
- [eip7702-revoker](https://github.com/Serge693/eip7702-revoker) and similar CLIs — remediation tools for an existing delegation; sign-safe evaluates the payload before it is signed.
- [sign-safe-skill](https://github.com/lrafasouza/sign-safe-skill) (lrafasouza) — an offline signing-time review CLI for **Solana** payloads with a similar verdict idea; different chain and runtime, and the origin of this package's name collision — credit where due.
- [revoke.cash](https://revoke.cash) — post-hoc inventory and revocation in the browser. Complementary to pre-signature review.

**What sign-safe adds:** pure decode → policy verdict → loggable explanation for agent loops, with no keys, no network, no signing, and enforcement owned by the signer integration. It complements signer-side policy engines and inventory tools rather than replacing them.

## What this is — and is not

This is a guideline layer, not a guarantee. An `ALLOW` means the inspected fields passed the configured rules — not that signing is safe. A `CONFIRM` requires independent review; unattended callers must stop. Block errors and `DENY` outcomes, prevent policy bypass, and bind each approval to the exact payload signed. Selector matches cannot establish behavior, including nested calls or proxies; this tool does not simulate execution, verify live state, or authenticate arbitrary EIP-712 schemas and domains. Supply trusted time and validate chain, contract, and schema context yourself. Defaults require deployment review, and business-policy coverage depends entirely on the rules you supply. No single tool is 100% protection.

## Scope and verification

An ALLOW means the decoded fields satisfy this policy. It does not authenticate the
signature, recover a signer, validate an arbitrary EIP-712 type schema/domain, verify
contract code, enforce nonce freshness, or simulate execution. The integration must
ensure the selected decoder corresponds to the actual schema being signed and
verify trusted domain/chain/contract identity. Human-readable token metadata is not
trusted or fetched. Opaque payloads must not bypass the inspection path.

Protocol references: [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702),
[ERC-2612](https://eips.ethereum.org/EIPS/eip-2612),
[Permit2 allowance interface](https://github.com/Uniswap/permit2/blob/main/src/interfaces/IAllowanceTransfer.sol),
and [signature-transfer interface](https://github.com/Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol).
Selector keys are the first four bytes of Ethereum Keccak-256 of the bundled canonical
signatures; the table is curated common coverage, not a measured popularity ranking.
