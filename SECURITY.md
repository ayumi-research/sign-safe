# Security policy

## Reporting a vulnerability

Open a **private security advisory via GitHub** (Security → Report a
vulnerability) or contact the maintainers directly. Do not post keys, live
signatures, wallet identifiers, or exploitable payloads in public issues. Use
synthetic reproductions and include the version, policy, expected verdict,
actual verdict, and integration assumptions.

Version 0.1.0 is experimental. There is no security audit certification, support
SLA, or stable v1 API. Reports against the current v0.x code are in scope; support
for historical releases is not promised.

## Scope and trust boundary

The package has no keys, wallet access, network requests, or signing capability.
It decodes supplied fields and **returns verdicts**. It does not prevent signing.
Enforcement belongs to the caller: policy bypass, an alternate signing path,
automatically accepting CONFIRM, or changing the inspected payload before signing
are integration concerns. Decoder mistakes, misleading explanations, and violations
of documented policy rules are library concerns and should be reported.

ALLOW means the inspected fields satisfy the supplied rules. It does not establish
signature validity, signer identity, schema authenticity, nonce freshness, contract
behavior, or on-chain state. Raw calldata selectors are hints, including for proxies
and nested calls. Permit2 signature-transfer recipients are unsigned context.

## Integration hardening

- Route every signing path through inspection; block DENY, errors, unknown verdicts,
  and unattended CONFIRM results. Human review must bind to the exact signing input.
- Freeze the complete payload, EIP-712 types and domain, chain, signer identity,
  policy, and execution context between review and signing. Authenticate schemas and
  contract identity outside this library. Do not accept attacker-selected decoders.
- Pass trusted Unix time as `now`; otherwise relative expiry checks do not run.
  Set explicit chains, deadline ceilings, amount caps, and narrowly scoped allowlists.
- Treat `PolicyEngine.evaluate` as a low-level interface for unmodified decoder
  output only. Protect policy files and engine state from untrusted modification.
- Apply payload-size, nesting, batch-size, and processing-time limits at the caller.
  The library currently has no resource budget. Treat exceptions as a signing stop.
- Amount limits apply per item in raw token units, not across requests or tokens.
  Keep durable spend budgets and nonce/state validation in the signer integration.
- Keep logs and input files private: payloads and error messages can contain account
  metadata or local paths. Never supply private keys or seed phrases to this API.
