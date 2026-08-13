# Novelty and claim boundary

**Frozen:** 2026-08-13
**Status:** scope gate for the v0.1 artifact and manuscript

## What already exists

- [SCITT Architecture, RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)
  defines receipt-carrying transparency infrastructure.  This project must not
  claim to have invented receipts or transparency registration.
- [RATS Architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html)
  defines evidence, appraisal, and attestation roles.  This project must not
  relabel local signed JSON as standards-conformant RATS Evidence.
- The individual
  [SCITT Permit profile v01](https://datatracker.ietf.org/doc/html/draft-munoz-scitt-permit-profile-01)
  already specifies pre-execution authorization, a canonical request digest,
  authority lineage, and closure records.  “Permit before action” and a
  PermitReceipt left edge are therefore prior art, not our novelty claim.
- The individual
  [AI Agent Execution Profile draft](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/00/)
  already addresses agent execution statements.  This artifact is not a
  competing standards profile.
- RIPE Atlas already provides public measurement metadata and result APIs,
  including [results/latest](https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/results-and-latest/)
  and a [streaming API](https://atlas.ripe.net/docs/apis/streaming-api/).

## The surviving research seam

The contribution tested here is the **composition boundary around an external
measurement platform**:

1. bind a narrowly scoped mandate to the semantic request an agent is allowed
   to send;
2. bind that request to the independent identifiers and state assigned by the
   external platform;
3. bind platform effects to a complete captured result window;
4. bind derived facts to an explicitly bounded public claim; and
5. return the earliest invalid transition rather than allowing a stronger leg
   to compensate for a missing one.

The motivating distinction is:

```text
well-formed != signed != authorised != executed-as-requested
            != completely observed != sufficient for the claim
```

The artifact operationalises that distinction across a real public
measurement service.  It does not claim priority for generic unauthorised-tool
benchmarks, first-bad-edge evaluation, signed receipts, or policy enforcement.

## Allowed empirical claims at v0.1

- In the frozen, author-designed 43-case corpus, all treatments accepted 22/22
  authorised controls; the witnessed composed verifier denied all 21 negative
  cases at the expected first bad edge.
- Hash-only, RIPE-native-only, Permit-only, and offline-composed treatments
  each expose specified blind spots in that same corpus.
- A separate witness is necessary for the designed collector-reissue case.
- The live pilot can demonstrate ordering and byte/digest binding across one
  prospective action: the public Permit preceded eight RIPE-assigned IDs, and
  the bounded closure records 32/32 narrow successes at 848 result-derived
  credits, subject to the limitations recorded in its result report.

## Prohibited claims

- No population false-accept rate, statistical generalisation, or superiority
  over deployed products.
- No claim that RIPE Atlas results are cryptographically signed by RIPE.
- No SCITT, RATS, COSE, or Permit-profile conformance claim for the local JSON
  envelopes.
- No claim that same-host witness execution provides compromise independence.
- No claim that a valid measurement proves global availability, security,
  legal compliance, RIPE NCC membership, or LIR status.
- No claim that the experiment key proves Anton Sokolov's identity, legal
  authority, or handwritten consent.  It proves only possession of the local
  research key after the interactive instruction recorded for the experiment.

## Minimum work before a thesis-strength inference

1. Diversify the 21 matched controls beyond their shared base and obtain
   external labels; the present pairs prevent blanket denial but are not
   independent observations.
2. Expand generated mutations beyond the seven authored operators.
3. Repeat captures across time and more than one external service.
4. Move the witness to an administratively and technically independent system.
5. Extend the existing latency, evidence-size, and localisation measurements
   across machines and implementations, and measure inter-rater agreement for
   any externally labelled cases.
6. Archive code/data with a DOI and obtain an independent reproduction.
