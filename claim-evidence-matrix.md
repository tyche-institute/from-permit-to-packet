# Claim–evidence matrix

| ID | Candidate manuscript claim | Status | Primary artifact | Boundary |
|---|---|---|---|---|
| C1 | The frozen replay contains 21 matched positive/negative pairs plus one unpaired clean baseline. | Observed | `corpus-index.json` | Authored corpus, not a population sample; controls are not all independent. |
| C2 | All treatments accepted 22/22 authorised controls; witnessed composition denied/localised 21/21 faults. | Observed | `results/summary.json`, `results/verdicts.jsonl` | Same-design ground truth; no external labels. |
| C3 | Hash-only and native-only each accepted 20/21 faults; Permit-only accepted 13/21; offline composition accepted 1/21. | Observed | `results/summary.json` | Treatment implementations are local prototypes, not products. |
| C4 | The generated sweep denied and localised 448/448 variations. | Observed after correction | `results/generated-mutations.json` | Seven authored operators; the sweep exposed a gate-placement bug and is developmental, not confirmatory. |
| C5 | A public signed Permit and exact request digest preceded RIPE measurement IDs. | Observed | `prospective/precommit/`, site commit `de25da7`, `prospective/execution/creation-response.json` | Public deployment timestamp is Tyche-controlled, not an independent transparency service. |
| C6 | RIPE assigned eight IDs for the frozen prospective body. | Observed | `prospective/execution/creation-response.json`; linked RIPE objects | RIPE assigned non-contiguous IDs; exact set must be reported. |
| C7 | Four scheduled sources returned 32/32 rows and 32/32 narrow successes. | Observed | `prospective/closure.json`, `prospective/capture-manifest.json` | One one-off observation; raw address-bearing rows kept outside the repo and remain at public RIPE APIs. |
| C8 | Result metadata accounts for 848 credits under the 1,060 ceiling. | Observed | `prospective/closure.json` | Account-level counter also included concurrent campaign spend and is not wholly attributable. |
| C9 | Browser replay agreed with collector semantics. | Observed | `prospective/witness/` | Same host, administration, network, and RIPE upstream; no Byzantine independence. |
| C10 | Witnessed verification had an approximately 273 μs median per replay bundle on the recorded host. | Observed | `results/performance.json` | Single-host descriptive run over the paired corpus; exact value may vary by rerun. |
| C11 | A GitHub-hosted runner passed 56 gates against both checkout and production artifacts. | Observed | `results/external-verifier.json`; Actions run `31729489880` | Separate from Zeus1, but same Tyche repository administration; not an independent audit. |
| C12 | The method improves real-world safety or reliability relative to deployed systems. | Not tested | — | Prohibited without an external comparative evaluation. |
| C13 | Local envelopes conform to SCITT, RATS, COSE, or the Permit draft. | Not tested | — | Prohibited; they are profile-local research JSON. |
| C14 | A successful result proves global availability, security, legal compliance, membership, or LIR status. | Unsupported | — | Prohibited semantic overclaim. |
| C15 | The experiment key proves verified human identity or legal authority. | Unsupported | — | Prohibited; it proves only local key possession after interactive instruction. |

Every public number in the abstract must map to C1–C11.  C12–C15 are explicit
negative controls for review, slides, press text, and thesis integration.
