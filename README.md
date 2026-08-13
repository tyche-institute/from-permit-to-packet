# From Permit to Packet v0.1

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21923744.svg)](https://doi.org/10.5281/zenodo.21923744)

An executable research case study of an AI-mediated public Internet
measurement workflow:

```text
mandate -> semantic action -> RIPE Atlas effect -> captured evidence -> bounded claim
```

The question is deliberately narrower than “is this JSON signed?”  The
prototype asks whether every transition remains within the mandate, binds to
the platform object actually created, covers the evidence used, and supports
only the final claim that was made.

## Current result

The deterministic replay corpus contains 21 matched positive/negative pairs
plus one unpaired clean baseline: 22 authorised controls and 21 designed
faults.  Every verifier accepts all 22 controls, so blanket denial cannot score
as safe.  The corpus compares five verifier treatments:

| Verifier | Authorised accepted | Designed faults rejected | Balanced accuracy |
|---|---:|---:|---:|
| SHA-256 manifest only | 22/22 | 1/21 | 0.524 |
| RIPE-native structural state only | 22/22 | 1/21 | 0.524 |
| Permit only | 22/22 | 8/21 | 0.690 |
| Composed, offline | 22/22 | 20/21 | 0.976 |
| Composed with witness | 22/22 | 21/21 | 1.000 |

The remaining offline blind spot is intentional: a compromised collector can
reissue a correctly signed, internally consistent cherry-picked statement.
The logically separate witness detects that disagreement.  It runs on the
same host and reads the same RIPE upstream, so it is **not** Byzantine
independence.

These counts demonstrate coverage of this author-designed corpus.  They are
not population error rates and do not estimate RIPE Atlas reliability.

A deterministic generated sweep then exercised 448 variations across seven
fault families.  The witnessed composed verifier denied and correctly
localised 448/448.  The first sweep exposed a misplaced evidence-summary check
inside the platform gate; the layer error was corrected before the frozen
result above was regenerated.  This is operator/input coverage, not an
independent adversarial evaluation.

The prospective pilot published its Permit and exact request digest before
action, then RIPE assigned IDs `200503603`, `200503604`, and
`200503606`–`200503611`.  Four explicit sources returned all 32 expected rows;
32/32 passed the narrow protocol checks and RIPE metadata accounts for 848
credits under the 1,060-credit ceiling.  The collector closure and separate
Chrome-CDP replay witness both verify, subject to the same-host/upstream
boundary.  A GitHub-hosted runner separately verified 56 gates against both
checked-out and production artifacts; it is off Zeus1 but remains under Tyche
repository administration.  See `prospective-pilot-result.md` and
`results/external-verifier.json`.

## Reproduce

Requirements: Python 3.11+ and `cryptography`.

```bash
cd experiments/from-permit-to-packet-v0.1
python3 src/run_experiment.py
python3 src/run_generated_mutations.py
python3 src/benchmark.py
python3 src/run_experiment.py
python3 -m unittest discover -s tests -v
sha256sum -c SHA256SUMS
```

`run_experiment.py` rebuilds every case, verdict, summary, and checksum.  Its
Ed25519 fixture keys are deterministic and explicitly marked
`test_fixture_key: true`; they provide repeatability, not operational trust.

## Artifact map

- `src/permit_to_packet.py` — ordered non-compensable gates and five verifier
  treatments.
- `src/run_experiment.py` — deterministic corpus builder and evaluator.
- `src/verify_prospective.mjs` — separately implemented 56-gate verifier for
  checked-out and production prospective evidence.
- `corpus/` — one complete bundle per control or fault.
- `results/verdicts.jsonl` — case-level verdicts and first-bad-edge output.
- `results/summary.json` — aggregate designed-corpus metrics.
- `results/generated-mutations.json` — seven deterministic mutation families.
- `results/performance.json` — single-host latency and artifact-size snapshot.
- `results/external-verifier.json` — successful GitHub-hosted checkout and
  production verification record.
- `prospective-pilot-protocol.md` — hypotheses and stopping rules frozen before
  the small live pilot.
- `prospective-pilot-result.md` — observed pilot timeline, identifiers, and
  claim boundaries.
- `prospective/capture-manifest.json` — allow-listed raw-capture filenames,
  byte sizes, and SHA-256 digests; detailed rows remain in the private Zeus1
  lab directory and at their public RIPE source URLs.
- `novelty-and-claims.md` — prior-art boundary and prohibited claims.
- `paper-outline.md` — manuscript architecture.
- `manuscript-v0.1.md` — evidence-bounded first manuscript draft.
- `claim-evidence-matrix.md` — allowed claims, primary artifacts, and negative
  controls against overclaim.
- `release/` — draft Zenodo metadata and explicit licence/public-source gates;
  no deposit is performed by this artifact.
- `SHA256SUMS` — local integrity manifest.

## Evidence boundaries

- The replay fields are privacy-minimised semantic fixtures derived from the
  Tyche campaign window of 2026-08-13; they are not the private authenticated
  API request bytes.
- RIPE Atlas public API responses arrive over TLS but are not RIPE-signed
  statements in this artifact.
- The local Ed25519 envelopes are a research profile.  They are not represented
  as SCITT receipts, RATS Evidence, or conformance to either standard.
- A valid chain supports a bounded observation window.  It does not prove
  global availability, security, legal compliance, RIPE NCC membership, LIR
  status, or the truth of an upstream assertion.
- The only authorised execution host for the pilot is `zeus1`.

## Licence and release status

Version 0.1.0. DOI: <https://doi.org/10.5281/zenodo.21923744>. Public source:
<https://github.com/tyche-institute/from-permit-to-packet>. Code is licensed
under Apache-2.0; the
manuscript, documentation, and public research data are licensed under CC BY
4.0. See `LICENSE.md` and `RELEASE-NOTES.md`. The public Observatory is an
explanatory demonstrator, not a production assurance service.

Build the manuscript PDF with:

```bash
pandoc manuscript-v0.1.md -o manuscript-v0.1.pdf --pdf-engine=xelatex \
  --toc -V geometry:margin=25mm -V colorlinks=true -V urlcolor=blue \
  -V mainfont="DejaVu Serif" -V sansfont="DejaVu Sans" \
  -V monofont="DejaVu Sans Mono"
```
