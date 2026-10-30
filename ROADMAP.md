# Roadmap

Version 0.1.0 is an experimental v0.x inspection library. APIs and verdict details
may change. Packaging readiness is separate from security assurance; v1 is not
promised on a date. Enforcement remains the caller's responsibility.

| Area | Done in v0.1.0 | Open |
| --- | --- | --- |
| Decoders | Canonical EIP-7702 tuples and unsigned intents; ERC-2612 fields; four Permit2 variants; 112 selector hints and four static ABI layouts; synthetic fixtures | Strict EIP-712 schema/domain binding; RLP; signature recovery; witness permits; nested ABI decoding; broader independent vectors and fuzzing; reject partial signature fields and ambiguous JSON |
| Policy | ALLOW/DENY/CONFIRM precedence; target/spender lists, denylist, chains, per-item amount and deadline limits; deterministic explanations; JSON and flat YAML rules | Reject duplicate JSON policy keys; cover unsigned transfer recipients in denylist checks; chain-specific trust; per-token cumulative budgets; immutable policy snapshots; bounded input processing |
| Packaging | MIT license, security scope, stdlib-only runtime metadata, CLI entry point, bundled selectors/fixtures, import scan, Python 3.11/3.13 CI definition | Resolve publication name collision; configure a real disclosure contact; execute hosted CI and Python 3.13 validation; independent security review; release provenance and repeatable release process |

The package never signs, holds keys, or contacts a network. Future validation
features must preserve the offline inspection boundary or live in separate adapters.
