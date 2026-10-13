# VulnProof

VulnProof is a standalone GenLayer Intelligent Contract for consensus-based
triage of software vulnerability reports.

It is inspired by the general problem area of security report dispatching, but
uses its own report schema, evidence evaluation flow, status model, and dispute
operation.

## Features

- Submit a vulnerability report with title, description, affected versions,
  and an HTTPS evidence/advisory URL.
- Store reports in a `TreeMap` using JSON-serialized records.
- Retrieve a report by ID and read the number of reports.
- Fetch public web evidence inside a non-deterministic function.
- Ask the GenLayer LLM to classify the evidence as `verified`, `rejected`,
  `disputed`, or `unresolved`.
- Use `gl.vm.run_nondet_unsafe` with a validator that checks response shape
  and independently agrees on the categorical result.
- Allow a verified/rejected report to be challenged and moved to `disputed`.

## Contract methods

| Method | Type | Purpose |
|---|---|---|
| `submit_report(title, description, affected_versions, evidence_url)` | write | Creates a report and returns its integer ID |
| `get_report(report_id)` | view | Returns a JSON string or `""` if missing |
| `get_report_count()` | view | Returns the allocated report count |
| `verify_report(report_id)` | write | Fetches evidence and performs consensus-backed triage |
| `dispute_report(report_id, challenge_reason)` | write | Challenges a verified/rejected result |

## State design

Each report contains:

- `id`
- `title`
- `description`
- `affected_versions`
- `evidence_url`
- `status`
- `verification_reason`
- `evidence_summary`
- `submitted_by`
- `verification_attempts`

The contract stores records as JSON strings in `TreeMap[u256, str]`, avoiding
unsupported arbitrary nested objects in persistent storage.

## Consensus design

Web retrieval and LLM assessment occur only inside `evaluate_evidence`, which
is passed to `gl.vm.run_nondet_unsafe`. The validator independently evaluates
the evidence and requires agreement on the status category. Free-form prose is
not required to match byte-for-byte.

The validator checks output structure, but consensus does not prove that a
report is objectively true. The result is evidence-based triage and must not be
presented as a formal security audit or proof that code is safe.

## Deploy in GenLayer Studio

1. Open https://studio.genlayer.com and connect a wallet.
2. Open **Run and Debug** (the wording may change with Studio updates).
3. Upload `contracts/vulnproof.py` as the contract file.
4. The constructor takes no arguments.
5. Deploy to **Studio Network** (chain ID 61999 for the network specified in
   the project brief).
6. Wait for the deployment transaction to finalize successfully.
7. Call `submit_report` with:
   - `title`: `Example library allows unauthorized file access`
   - `description`: a specific vulnerability claim
   - `affected_versions`: `1.0.0 through 1.2.3`
   - `evidence_url`: a real public HTTPS advisory page
8. Use the returned ID with `get_report`.
9. Call `verify_report` with that ID. This is a consensus transaction and may
   take longer and cost more than a view call.
10. Read `get_report` again and inspect `status`, `verification_reason`,
    `evidence_summary`, and `verification_attempts`.
11. If a result is `verified` or `rejected`, test `dispute_report` and confirm
    that the report is marked `disputed`.
12. Call `verify_report` again to evaluate the disputed report with its challenge
    reason included as context.

Use an actual public advisory URL for a meaningful test. A generic homepage
or inaccessible URL will likely produce `unresolved`.

## Testing and limitations

`tests/test_contract_structure.py` performs offline structural checks. It does
not emulate GenLayer consensus or prove deployment compatibility. Final
validation must happen in GenLayer Studio using the write methods above.

External pages can change, be unavailable, or contain malicious prompt-injection
text. The prompt treats page content as untrusted evidence, but this does not
eliminate all manipulation risk. A production-grade version should add source
allowlists, a multi-source evidence model, audit history, and a formal appeal
policy. This prototype deliberately does not claim to execute or verify the
actual vulnerable code.
