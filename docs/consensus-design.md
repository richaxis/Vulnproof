# VulnProof consensus and state design

## Why GenLayer is used

The result depends on live external evidence and semantic interpretation of
that evidence. A normal deterministic contract cannot independently fetch and
interpret a changing web page in the same way. VulnProof places web retrieval
and LLM assessment in a non-deterministic function and uses a validator to
check the structure and categorical result before the contract updates state.

## State transitions

- `submitted` -> `verified`, `rejected`, `disputed`, or `unresolved` after
  `verify_report`.
- `unresolved` -> any verification outcome after another `verify_report`.
- `verified` -> `disputed` via `dispute_report`.
- `rejected` -> `disputed` via `dispute_report`.
- `disputed` -> any verification outcome after `verify_report`; the challenge
  reason is included as context for the evidence evaluation.

## Validator policy

The validator rejects malformed leader outputs. It independently re-runs the
evidence evaluation and accepts only if its status matches the leader status.
Reason text is not compared exactly because independent model responses can
differ in wording.

## Threat model and limitations

- The evidence URL and page contents are untrusted.
- The prompt explicitly tells the model to treat page content as data, not
  instructions.
- One URL can be stale, incomplete, or manipulated.
- Consensus agreement is not equivalent to a security audit.
- The prototype does not fetch package source code, run tests, or prove a fix.
- For production use, add trusted-source policies, multiple independent
  references, immutable audit events, appeal/review rules, and rate limiting.
