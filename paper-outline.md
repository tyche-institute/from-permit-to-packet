# Paper outline — From Permit to Packet

## Working title

**From Permit to Packet: Composing Agent Authority with Public Internet
Measurement Evidence**

## One-sentence thesis

A valid signature or valid platform object cannot compensate for a missing
authority/effect/evidence/claim transition; an ordered, non-compensable
verifier can expose and localise those failures across a real public
measurement workflow.

## Candidate contributions

1. A five-transition model for agent-mediated action through an external
   service: mandate, action, platform effect, evidence, and bounded claim.
2. An executable verifier returning the earliest invalid transition.
3. A versioned fault corpus spanning scope escalation, platform substitution,
   evidence omission, collector equivocation, and semantic overclaim.
4. A prospective RIPE Atlas case study that publicly commits the Permit before
   the platform assigns measurement identifiers.
5. An interactive “Breakable Observatory” that makes treatment blind spots
   inspectable case by case.

## Proposed structure

1. **Introduction** — the permit/packet gap and why valid artifacts do not
   compose automatically.
2. **Background and related work** — SCITT RFC 9943, RATS RFC 9334, the Permit
   profile draft, AI-agent execution draft, RIPE Atlas APIs, and neighbouring
   unauthorised-tool benchmarks.
3. **Threat model** — over-scoped agent, substituted platform effect,
   incomplete/equivocating collector, and overclaiming publisher.
4. **Model** — typed objects, canonical digests, ordered gates, trust
   boundaries, and the no-compensation rule.
5. **Implementation** — local Ed25519 research envelopes and explicit
   non-conformance boundary.
6. **Study design** — replay corpus, five verifier treatments, prospective
   pilot, outcomes, and stopping rules.
7. **Results** — false accepts per designed corpus, first-edge localisation,
   offline witness blind spot, pilot trace, verification latency, and bytes.
8. **Threats to validity** — authored cases, convenience probes, unsigned
   upstream, same-administration witness, one action, and retrospective replay.
9. **Discussion** — what an external platform would need to sign; where SCITT
   receipts and RATS appraisal can connect without inheriting trust.
10. **Conclusion** — evidence-carrying action as explicit transition checks,
    not trust by proximity.

## Figures and tables

- Figure 1: permit-to-packet transition graph and verifier cut points.
- Figure 2: interactive fault matrix exported from the Observatory.
- Figure 3: prospective timestamp/digest/measurement-ID sequence.
- Table 1: five treatments and their trust assumptions.
- Table 2: 21 fault operators, expected first bad edge, and verdicts.
- Table 3: evidence size and verification latency.

## Next experiments that add real scholarly value

- Diversify the current 21 matched authorised lookalikes and add external labels.
- Property-based mutation testing over typed requests and claims.
- Race experiments for expiry, revocation, and delayed platform assignment.
- Independent witness on a separately administered host and network.
- Cross-platform replication using a second externally assigning service.
- Human study: can reviewers identify unsupported claims from raw artifacts
  versus the composed verdict?
- Standards experiment: express the same bindings with actual COSE/SCITT
  profiles while retaining the external-platform receipt boundary.

## Publication positioning

The strongest first output is an artifact-backed systems/security paper or
measurement workshop paper, with a separate software/data release only if each
has an independent scholarly purpose.  Do not market the current version as a
standard, production assurance mechanism, or statistically representative
network study.
