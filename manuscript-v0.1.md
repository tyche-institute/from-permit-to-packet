---
title: "From Permit to Packet: Composing Agent Authority with Public Internet Measurement Evidence"
author:
  - "Anton Sokolov · Tyche Institute · ORCID 0000-0003-2452-7096"
date: "13 August 2026"
keywords:
  - AI agents
  - authorization
  - evidence composition
  - RIPE Atlas
  - SCITT
  - RATS
  - reproducible research
---

# Abstract

An authenticated AI agent can issue a syntactically valid request that exceeds
its mandate; an external service can create a valid object that differs from
the request; a signed collector can omit evidence; and an internally consistent
report can make a claim stronger than its observations support. These are
composition failures: each component may pass its local check while the chain
as a whole fails to justify the final claim. We study this problem in an
agent-mediated RIPE Atlas workflow and model five non-compensable transitions:
mandate to action, action to platform effect, effect to evidence, evidence to
bounded claim, and artifact integrity. An ordered verifier returns the earliest
invalid transition rather than a single undifferentiated signature result.

The evaluation combines three forms of evidence. First, an author-designed
matched corpus contains 21 positive/negative pairs plus one clean baseline. All
five verifier treatments accept 22/22 authorised controls. Across 21 designed
faults, SHA-256-only and platform-native treatments each reject 1, a Permit-only
treatment rejects 8, an offline composed treatment rejects 20, and a composed
treatment with a logically separate witness rejects and correctly localises all
21. Second, a deterministic seven-family mutation sweep rejects and localises
448/448 generated variations. Third, a prospective action publishes a signed
Permit and the digest of an exact 3,340-byte request before RIPE assigns eight
measurement identifiers. Four explicit probes return all 32 scheduled one-off
results; 32/32 pass narrow protocol checks at 848 result-derived credits under
a 1,060-credit ceiling. A GitHub-hosted implementation subsequently passes 56
gates over both repository and production artifacts.

The results establish conformance only for the versioned corpus and bounded
pilot. RIPE public API rows are not RIPE-signed statements; the witness shares
Tyche administration and the RIPE upstream; and the work claims neither SCITT
nor RATS conformance, population error rates, global availability, legal
compliance, or independent audit. The contribution is an executable method for
making authority-to-claim composition failures inspectable.

# 1. Introduction

Security accounts of autonomous or semi-autonomous agents often begin with an
identity and end with an audit log. The difficult middle is frequently left
implicit. A principal may allow an agent to perform one bounded action, but the
agent sends a richer request. A service may accept that request yet create a
different object. A collector may retrieve only part of the resulting state.
Finally, a publisher may turn a local observation into an expansive statement.
None of those failures is repaired by the fact that some JSON object was
signed.

This distinction matters because cryptographic integrity, authorization,
platform state, evidentiary coverage, and claim sufficiency answer different
questions. A valid signature identifies control of a key over bytes. It does
not itself show that the signer possessed relevant authority, that the bytes
were sent, that the remote effect matches them, that all material results were
retained, or that the final statement follows from those results. Treating one
check as a substitute for another produces what this paper calls
*compensating verification*: a strong later artifact is incorrectly allowed to
compensate for a broken earlier transition.

RIPE Atlas is a useful public setting in which to make the problem concrete.
Users submit measurement definitions and source selections; RIPE Atlas assigns
measurement identifiers and schedules probes; public APIs expose metadata and
results; and a downstream analyst derives a claim. The platform therefore
creates an externally assigned effect that does not exist when the principal
authorises the action. Its credit model also gives authorization a measurable
resource dimension. At the same time, the platform is not an attestation
service for this experiment: its public rows are retrieved over TLS but are not
operator-signed statements supplied for third-party offline verification.

The study asks four research questions:

- **RQ1 — separation:** Which designed failures are detected when a verifier
  checks only file integrity, only native platform state, only pre-execution
  authority, or the composed transition chain?
- **RQ2 — non-trivial acceptance:** Can the composed verifier reject the
  designed faults without achieving its score through blanket denial?
- **RQ3 — temporal binding:** Can a publicly committed Permit bind an exact
  request to platform identifiers that do not yet exist and later to a bounded
  evidence window?
- **RQ4 — reproducibility:** Can a verifier executed away from the action host
  reproduce the prospective verdict using public, privacy-minimised artifacts?

The paper makes four bounded contributions. It defines an ordered
authority-to-claim transition model; provides an executable matched corpus and
five verifier treatments; records a prospective RIPE Atlas trace whose Permit
precedes the platform-assigned IDs; and publishes a production Observatory,
tests, manifests, and an infrastructure-separated verification workflow. It
does not claim that Permits, evidence receipts, first-failure diagnostics, or
transparency mechanisms are new primitives. The narrower contribution is their
composition around an external platform effect.

# 2. Background and related work

## 2.1 Delegated authority and attenuation

Delegation systems distinguish authenticated identity from the authority to
perform a particular operation. SPKI/SDSI makes authorization certificates and
delegation explicit [1]. Macaroons show how bearer credentials can be narrowed
by contextual caveats concerning where, when, by whom, and for what purpose a
request may be used [2]. These systems motivate the Permit in this experiment:
the relevant object is not an assertion that an agent exists, but a bounded
grant constraining target, action shape, execution host, source count, time,
automatic replenishment, and cost.

The experiment does not implement SPKI or Macaroons. Its local Permit is a
signed research object designed to isolate transition semantics. The important
inheritance from authorization work is monotonicity: an execution may stay
within or narrow its grant, but should not silently enlarge it. Positive
controls therefore vary permitted values without breaking containment, while
matched negatives cross one corresponding boundary.

## 2.2 Signed statements, provenance, and transparency

End-to-end provenance systems demonstrate the value of checking transitions
instead of only final artifacts. In-toto records and verifies the steps of a
software supply chain so that compromise at one stage cannot be hidden by a
valid final package [3]. Certificate Transparency uses append-only logs,
inclusion evidence, and gossip to make conflicting views detectable [4].
Sigstore applies identity-bound signing and a public transparency log to
software artifacts [5]. These systems address different objects, but share the
principle that later integrity does not retroactively legitimate an earlier
untrusted step.

The IETF SCITT architecture generalises signed statements and transparency
services. A Signed Statement can be registered in a verifiable data structure;
the resulting Receipt supports offline verification of inclusion, while the
registration policy and append-only history support accountability [6]. SCITT
also makes an important negative point: transparency does not prevent a
dishonest or compromised issuer. This study uses that boundary directly. Its
local Ed25519 envelopes are signed statements in the ordinary sense, but are
not SCITT Signed Statements, COSE receipts, or entries in a SCITT transparency
service.

## 2.3 Evidence appraisal and role separation

The RATS architecture distinguishes an Attester that produces Evidence, a
Verifier that applies appraisal policy, and a Relying Party that uses
Attestation Results for an application decision [7]. It also warns that when
roles are aggregated in one entity, implementers must reassess the assumed
security properties. This paper follows the role distinction but not a RATS
wire format. The RIPE rows, collector statement, witness statement, and final
claim are not represented as standards-conformant RATS conceptual messages.

Role separation is central to the strongest designed fault. If a collector can
change an evidence index, recompute the summary, rewrite the claim, and sign the
new internally consistent chain, an offline verifier with only the collector's
view cannot detect equivocation. A witness with a prior semantic index can.
However, logical separation is not compromise independence: both Tyche
statements were produced on the same host, administered by the same
organisation, and read the same RIPE upstream.

## 2.4 Emerging agent-action profiles

The SCITT Permit Internet-Draft binds a pre-execution authorization decision to
canonical request bytes and pairs it with a post-dispatch Closure Record whose
dispatch digest can be compared with the authorised digest [8]. The AI Agent
Execution Profile Internet-Draft describes signed, hash-chained records of
material agent actions and maps agent roles into SCITT [9]. These drafts are
direct prior art for request digests, closure records, execution statements,
and evidence chains. They are works in progress, not standards, and this
prototype does not claim conformance to either.

The remaining seam is the platform join. A dispatch digest can show that the
authorised bytes match recorded dispatch bytes, yet an external service may
assign identifiers, normalise definitions, schedule only some sources, or
produce state whose evidentiary meaning is narrower than a later claim. The
present model makes those joins explicit and independently falsifiable.

## 2.5 RIPE Atlas as an external effect producer

RIPE Atlas is a global distributed Internet measurement system operated by the
RIPE NCC. Probes receive measurement instructions through the platform and
return results to its infrastructure [10,11]. User-defined measurements specify
definitions, probe selection, and timing; supported types include ping,
traceroute, DNS, TLS, and NTP [12]. Measurements consume credits and are
assigned platform states such as Specified, Scheduled, Ongoing, and Stopped.
Public measurement metadata and results can be retrieved through REST APIs
[12,13].

Atlas therefore offers a real, inspectable platform effect without giving the
experiment control of the assigned identifiers. It also exposes important
limits. Probe selection is not a population sample, measurement success is
protocol-specific, and public API retrieval is not equivalent to an operator
signature over the semantics used by this paper. The prospective claim is
accordingly restricted to one window, four explicit probes, eight definitions,
and narrow per-protocol success predicates.

# 3. Transition model

## 3.1 Artifacts and actors

The model contains six principal artifacts:

1. a **Permit** signed before action and containing authority limits;
2. an **action request** represented by exact canonical bytes and their digest;
3. a **platform effect** containing externally assigned measurement IDs and
   native definition/state fields;
4. an **evidence index** binding those IDs to captured metadata, results,
   source coverage, freshness, and derived counts;
5. a **claim** restricted to the facts and caveats supported by that evidence;
6. an **integrity manifest** binding retained public artifact bytes.

The principal authorises an operator-controlled agent. RIPE Atlas produces the
external effect. A collector retrieves and summarises public platform data. A
witness may retain a separately signed semantic view. A verifier appraises the
chain, and a reader or automated relying party consumes the verdict.

## 3.2 Ordered, non-compensable gates

The verifier evaluates the following gates in order:

1. **Integrity:** retained components match the SHA-256 manifest.
2. **Mandate → action:** the Permit signature and validity interval pass; the
   exact request digest, target, definition set, sources, duration, execution
   host, automatic top-up rule, and credit ceiling are authorised.
3. **Native platform effect:** the external object has the required native
   structure and state.
4. **Action → effect:** assigned definitions, sources, identifiers, and time
   bounds correspond to the request.
5. **Effect → evidence:** the capture covers the assigned ID set and scheduled
   sources, falls inside the accepted time window, and derives its summary from
   the retained index.
6. **Evidence → claim:** quantitative facts equal the evidence and qualitative
   language remains a bounded observation with required caveats.
7. **Witness agreement:** when the witnessed treatment is selected, the
   collector and witness semantic indices agree.

On failure the verifier returns `DENY`, a machine-readable gate, and the first
bad transition. Ordering is diagnostic, not compensatory: once an earlier edge
fails, later validity cannot change the verdict. A multi-fault case tests that
the earliest edge remains stable.

## 3.3 Threat model

The designed adversary may modify unsigned content, rehash modified content,
substitute a valid platform object, omit evidence, alter a summary, overstate a
claim, or control the collector's signing key. It may also create multiple
faults. The adversary does not break Ed25519, SHA-256, TLS, GitHub, RIPE Atlas,
or the host operating system. The witness treatment assumes the adversary does
not simultaneously control both the collector and the witness view.

The prospective case is weaker than this abstract treatment assumption. The
collector and witness use distinct statements and keys but share Tyche
administration, the Zeus1 host and network, and RIPE as upstream. The GitHub
runner removes Zeus1 from repeated verification but remains under the same
repository administration. These facts are reported as boundaries rather than
treated as independence.

## 3.4 Cryptographic profile

Fixture and pilot envelopes use Ed25519 [14]. Structured values are serialized
by recursively sorting object keys and emitting compact UTF-8 JSON. The exact
API request is additionally retained as bytes, so its SHA-256 is computed over
the actual 3,340-byte body rather than a later reconstruction. Canonicalization
is required for repeatable hashing and signing [15], but the prototype's local
serializer is not claimed to implement RFC 8785 JCS. Fixture private keys are
deterministic and explicitly marked as test keys; pilot private keys remain
outside the public artifact.

# 4. Study design and implementation

## 4.1 Five verifier treatments

Five treatments isolate the information available at appraisal time:

- **SHA-256 only** checks the retained artifact manifest.
- **Platform native only** checks the expected RIPE object structure/state.
- **Permit only** verifies the Permit and mandate-to-action containment.
- **Composed offline** checks integrity and every local transition through the
  bounded claim.
- **Composed + witness** adds agreement with a separately signed semantic
  evidence index.

The treatments are intentionally not competitors of equal scope. They expose
which semantic classes each information boundary cannot observe.

## 4.2 Matched replay corpus

The replay corpus contains 43 bundles: 21 designed negative cases, 21 matched
authorised controls, and one unpaired clean baseline. Each pair varies the same
semantic dimension on opposite sides of its policy boundary. For example, a
negative target substitution changes the target outside the Permit, whereas
its positive twin changes target and Permit consistently; a negative evidence
omission removes an assigned measurement, whereas its positive twin only
reorders a complete set. This structure prevents a verifier that rejects every
variation from appearing safe.

The faults cover target substitution, probe-budget and duration escalation,
automatic replenishment, required-definition removal, execution-host escape,
invalid Permit signature, request/effect mismatch, platform-definition and
time substitution, measurement omission, summary cherry-picking, stale
capture, three forms of semantic overclaim, missing boundaries, platform state
failure, unrehashed integrity tampering, collector reissue, and a multi-fault
first-edge case.

Expected ground truth and expected first bad edge are authored with the cases.
The corpus measures conformance to those authored expectations. It does not
estimate how often such failures occur in deployed agents or RIPE Atlas.

## 4.3 Generated variations

A seeded generator (`20260813`) creates 64 variants in each of seven operator
families: target substitution, probe-budget escalation, duration escalation,
execution-host escape, platform-effect substitution, evidence-summary
cherry-picking, and claim overreach. The 448 cases broaden input coverage around
known fault operators but are not an independent adversarial sample.

The first developmental sweep exposed a layer-placement defect: the native
platform treatment incorrectly examined a local evidence summary. The check was
moved to effect-to-evidence before the reported corpus and sweep were frozen.
This history is disclosed because the generator informed implementation
correction; it is not a preregistered confirmatory result.

## 4.4 Prospective protocol

Before submission to RIPE Atlas, the experiment published the exact canonical
request, SHA-256 digest, public experiment key, signed Permit, authority limits,
and an empty measurement-ID list. The request contained eight public one-off
definitions for `tyche.institute`: IPv4 and IPv6 variants of ping, traceroute,
DNS, and TLS certificate retrieval. It named probes 28, 81, 6349, and 6569,
disabled automatic top-up, authorised only `zeus1`, and capped expenditure at
1,060 credits.

The action was sent through an authenticated Chrome session on Zeus1. The
initial session-authenticated attempt returned HTTP 403 before creation because
the RIPE endpoint required `X-Requested-With`. Adding that transport header did
not change the committed JSON body. The accepted response then assigned eight
measurement IDs.

The collector retrieved public metadata and results, retained a private raw
capture on Zeus1, and published a privacy-minimised source index and file-hash
manifest. A Chrome-CDP replay used separate collection code and a separate key
to compare measurement IDs, counts, narrow successes, and the semantic source
index. Raw rows containing network-address fields are excluded from the public
repository.

## 4.5 Outcome predicates

For the prospective pilot, success is deliberately narrow. A ping row passes
when all requested replies are represented; traceroute passes when the
destination response is reached; DNS passes when the requested answer is
returned; and TLS passes when a certificate chain is returned. These checks do
not establish service availability, path quality, certificate policy
compliance, or security. Credit usage is derived from RIPE per-result metadata
and checked against the Permit ceiling.

## 4.6 External reproduction

A Node implementation in GitHub Actions verifies Ed25519 envelopes, the exact
request digest, target and source constraints, disabled top-up, credit ceiling,
platform ID identity, claim counts, and public capture-manifest hashes. It runs
against both checked-out repository artifacts and production URLs. Its 56 gates
are a second implementation of the prospective appraisal path, not of every
Python replay-corpus treatment.

## 4.7 Metrics

For matched cases, the study reports authorised acceptance, designed-fault
detection, balanced accuracy, and correct first-edge localisation. Balanced
accuracy is the mean of the authorised acceptance rate and negative detection
rate. Because the corpus is fully authored and small, no confidence intervals
or population inference are reported. Generated variations are reported as
exact seeded coverage. Performance uses `perf_counter_ns`; each observation is
a full 43-case pass divided by case count, repeated 2,000 times on the recorded
Zeus1 software environment.

# 5. Results

## 5.1 Matched corpus

| Treatment | Authorised accepted | Faults denied | Balanced accuracy | Correct first-edge locations |
|---|---:|---:|---:|---:|
| SHA-256 only | 22/22 | 1/21 | 0.524 | 1/21 |
| Platform native only | 22/22 | 1/21 | 0.524 | 1/21 |
| Permit only | 22/22 | 8/21 | 0.690 | 8/21 |
| Composed offline | 22/22 | 20/21 | 0.976 | 20/21 |
| Composed + witness | 22/22 | 21/21 | 1.000 | 21/21 |

All treatments accept all authorised controls, answering RQ2 within the corpus:
the composed result is not produced by blanket denial. The hash-only treatment
detects unrehashed tampering but accepts 20 semantically changed faults after
their artifacts are made internally hash-consistent. The native treatment
detects the stopped-platform case but has no authority or claim context. The
Permit treatment detects all eight mandate-to-action faults and accepts 13
later-chain faults.

The composed offline treatment rejects and correctly locates 20 faults. Its
sole false accept is `D20_collector_reissued_cherry_pick`: the collector removes
part of the evidence index, recomputes the summary and claim, and re-signs the
consistent chain. Nothing in that collector-controlled view contradicts
itself. The witnessed treatment compares the prior semantic index and returns
`evidence.witness_disagreement`, detecting the 21st fault. This is evidence for
the value of a separate view, conditional on its uncompromised and
non-colluding status.

## 5.2 Generated sweep

The witnessed composed verifier rejects 448/448 generated variations and
reports the expected first bad edge in 448/448. Each of the seven families
contributes 64 cases. The exact result answers an implementation-coverage
question only; it is not an empirical estimate of detection against unknown
attacks.

## 5.3 Prospective trace

The public precommit digest was:

```text
ae3c95459fba6e8a3fb1120aeecf47529a214aaa0bfacceb45ee0a7d051c91ad
```

The accepted RIPE response assigned IDs `200503603`, `200503604`, and
`200503606`–`200503611`. Each of the four requested probes was scheduled in
each definition. The capture retained all 32 expected rows, and 32/32 passed
the narrow protocol predicates. RIPE per-result metadata accounts for 848
credits, below the 1,060-credit Permit ceiling.

The collector Closure verifies and returns `ALLOW` with no first bad edge. The
Chrome-CDP witness agrees on identifiers, result count, success count, and
source index. The prospective trace therefore answers RQ3 for this action: the
pre-action request digest is joined to subsequently assigned platform IDs and
then to a complete bounded evidence index. It does not prove that the public
RIPE semantics themselves are signed or independently witnessed.

## 5.4 Infrastructure-separated verification

The GitHub-hosted runner passes all 56 gates over both its checkout and the
public production URLs. Both paths reproduce the request digest, eight IDs, 32
rows, 32 narrow successes, and 848 credits. This answers RQ4 in the limited
sense that appraisal no longer depends on executing the verifier on Zeus1. It
does not create an independent auditor because Tyche controls the repository,
workflow, and public presentation.

## 5.5 Cost

| Treatment | Median µs/bundle | p95 µs/bundle |
|---|---:|---:|
| Platform native only | 0.957 | 1.008 |
| SHA-256 only | 51.592 | 54.160 |
| Permit only | 85.596 | 87.779 |
| Composed offline | 208.974 | 219.822 |
| Composed + witness | 273.444 | 362.659 |

The clean replay bundle is 11,341 bytes, the signed prospective Closure is
10,309 bytes, and the 17 retained private capture JSON files total 80,469
bytes. These are descriptive results from one Python 3.12.3 / `cryptography`
49.0.0 environment on Linux x86-64, not cross-machine performance claims.

# 6. Discussion

## 6.1 What the treatment differences mean

The treatment comparison makes the semantics of common assurance shortcuts
visible. A manifest can establish that retained bytes equal a published digest;
it cannot decide whether a rehashed request was authorised. A platform-native
check can establish that an object is structurally plausible and in an
expected state; it cannot know what a principal allowed. A Permit can prevent
scope escalation; it cannot establish that later evidence is complete. A
complete evidence index still cannot justify language broader than its window.

The implication is not that every application needs seven gates. It is that a
relying party should name which transition supports which claim. An
architecture that stops after signature verification should make the resulting
unknowns explicit rather than inheriting authority or truth from the signature.

## 6.2 First-bad-edge diagnostics

A Boolean result is often insufficient for repair. If a substituted target and
an incomplete capture occur together, fixing the capture does not make the
action authorised. Ordered first-bad-edge reporting makes this precedence
explicit. It also prevents later checks from obscuring the earliest policy
failure. The order is application policy, however, not a universal theorem;
other workflows may place native safety gates before authority or distinguish
more granular evidence stages.

## 6.3 Temporal evidence and externally assigned identifiers

The prospective trace supplies evidence unavailable in a retrospective fixture:
the RIPE IDs are absent when the Permit is published. Their later appearance
shows an actual temporal join from authorised request bytes to an externally
created object. This is more informative than inserting known IDs into a signed
record after the fact, while remaining weaker than an operator-issued receipt
that cryptographically binds the request and resulting effect.

The clean next standardisation path would keep the semantic gates while
replacing local envelopes with standards-based signed statements and receipts.
A SCITT Permit and Closure could bind authorisation and dispatch; a transparency
service could provide inclusion and non-equivocation evidence; a RATS appraisal
could cover execution-platform trust where relevant; and a domain adapter could
bind the external platform effect and evidence semantics. The present artifact
tests the joins without claiming those standards have been implemented.

## 6.4 Independence as a graded property

The D20 result demonstrates why a separately signed statement is not enough if
its producer shares the collector's compromise domain. Independence has at
least four dimensions: key separation, software-path separation,
administrative separation, and upstream separation. The pilot achieves the
first two only partially and the GitHub run adds execution-host separation.
Future work should place the witness under a different administrator and
network, retain a prior commitment in an append-only service, and compare more
than one upstream representation where the platform permits it.

## 6.5 Thesis and publication value

For a thesis on agent authority or verifiable action evidence, the project
serves as a worked empirical bridge between abstract delegation and observable
external effects. Its value is methodological: it shows how to turn a claim of
authority propagation into falsifiable joins, matched controls, typed failure
attribution, a prospective trace, and a reproducible artifact. It should not be
used as evidence that RIPE Atlas itself is unreliable or that one witness
architecture is sufficient for deployment.

# 7. Threats to validity

**Construct validity.** The authored gates operationalise one model of
authority-to-claim composition. Other applications may require different
semantics or ordering. The narrow protocol predicates are intentionally weaker
than availability or security claims.

**Internal validity.** The same author designed the corpus and the main Python
verifier. Matched controls reduce the risk of trivial rejection, and the Node
prospective verifier reduces implementation-path dependence, but neither
constitutes independent ground-truth annotation. The mutation generator helped
find and correct a gate-placement defect before the final run.

**External validity.** The corpus has 21 designed faults and 22 authorised
controls. The live trace is one action over four convenience-selected probes
and one target. No prevalence, ecosystem coverage, or RIPE reliability
conclusion follows.

**Evidence validity.** RIPE Atlas public API rows are upstream data retrieved
over TLS, not RIPE-signed evidence in this artifact. The collector and witness
share an upstream, host, network, and administrator. The GitHub runner is
infrastructure-separated but not institutionally independent.

**Temporal validity.** Internet state, probe connectivity, software versions,
standards drafts, and public endpoints change. Results are version- and
window-bound. The eight one-off measurements are stopped historical objects;
they are not a continuing monitor.

# 8. Ethics, privacy, and responsible use

The pilot uses public RIPE Atlas measurements with automatic top-up disabled
and an explicit credit ceiling. It targets the Institute's own public domain
and performs ordinary ping, traceroute, DNS, and TLS-certificate measurements.
The public artifact excludes authenticated API credentials, private keys, and
raw address-bearing result rows. The raw capture is retained privately on
Zeus1; a privacy-minimised manifest exposes filenames, sizes, and SHA-256
digests for integrity checking.

The Observatory labels the work as a research prototype and states prohibited
inferences. A valid bundle must not be presented as proof of legal authority,
human identity, compliance, RIPE NCC membership, LIR status, general security,
or global availability. Researchers reusing the software remain responsible
for platform terms, measurement ethics, target permission, privacy, and credit
budgets.

# 9. Reproducibility and availability

The public release contains source code, deterministic fixture keys, the 43
case bundles, case-level verdicts, generated-sweep results, performance
metadata, prospective precommit and Closure artifacts, the privacy-minimised
capture manifest, tests, and SHA-256 manifests. Reproduction requires Python
3.11 or later and `cryptography`. The core commands rebuild the corpus and
results, execute the mutation sweep and microbenchmark, run five unit tests,
and verify the file manifest.

The public Observatory is available at
<https://tyche.institute/lab/from-permit-to-packet/>. The release repository is
<https://github.com/tyche-institute/from-permit-to-packet>; the archival release
is <https://doi.org/10.5281/zenodo.21923744>. Code is
licensed under Apache License 2.0; the manuscript, documentation, and public
data are licensed under CC BY 4.0. Private raw capture and private keys are not
part of the release.

# 10. Conclusion

The study supports a modest but useful result: explicit, ordered transition
gates can distinguish integrity, authority, native platform effect, evidence
coverage, and claim sufficiency in a real agent-mediated public measurement
workflow. The matched corpus shows why no single local treatment observes the
whole chain; the prospective trace demonstrates temporal binding to platform
identifiers that did not exist at authorisation time; and public verification
shows that the bounded appraisal can be repeated away from the action host.

The decisive next work is institutional rather than cosmetic: independent
labeling, a separately administered witness, cross-platform replication,
property-based request generation, and standards-based receipts. Until then,
the artifact is a reproducible research profile and thesis-grade pilot, not a
production assurance service or certification mechanism.

# Declarations

**Author contributions.** Anton Sokolov conceived the study, designed the
artifact and corpus, operated the prospective pilot, analysed the results, and
wrote the manuscript.

**Generative-AI assistance.** OpenAI Codex was used under author direction for
software implementation, test generation, data checking, manuscript drafting,
and editorial revision. The author selected the research questions, authorised
the live action, reviewed the evidence boundaries, and remains responsible for
the work and its claims.

**Funding.** No external funding was received for this study. RIPE Atlas
credits already available to the account were used for the bounded pilot.

**Competing interests.** The author is affiliated with Tyche Institute, which
operates the repository, Observatory, collector, witness, and verification
workflow described here. No claim of institutional independence is made.

**Data and code availability.** Public, privacy-minimised evidence and code are
released through the repository and archival DOI identified in Section 9. Raw
network-address-bearing capture data and secret keys are not publicly released.

# References

1. Ellison, C., Frantz, B., Lampson, B., Rivest, R., Thomas, B., and Ylonen,
   T. *SPKI Certificate Theory*. RFC 2693, IETF, 1999.
   <https://www.rfc-editor.org/rfc/rfc2693>
2. Birgisson, A., Politz, J. G., Erlingsson, Ú., Taly, A., Vrable, M., and
   Lentczner, M. “Macaroons: Cookies with Contextual Caveats for Decentralized
   Authorization in the Cloud.” NDSS, 2014.
   <https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/>
3. Torres-Arias, S., Afzali, H., Kuppusamy, T. K., Curtmola, R., and Cappos,
   J. “in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes.”
   *USENIX Security 2019*, pp. 1393–1410.
   <https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias>
4. Laurie, B., Langley, A., and Kasper, E. *Certificate Transparency*.
   RFC 6962, IETF, 2013. <https://www.rfc-editor.org/rfc/rfc6962>
5. Chandrasekaran, A. et al. “Sigstore: Software Signing for Everybody.”
   *ACM CCS 2022*. <https://doi.org/10.1145/3548606.3560596>
6. Birkholz, H. et al. *An Architecture for Trustworthy and Transparent
   Digital Supply Chains*. RFC 9943, IETF, 2026.
   <https://www.rfc-editor.org/rfc/rfc9943>
7. Birkholz, H., Thaler, D., Richardson, M., Smith, N., and Pan, W. *Remote
   ATtestation procedureS (RATS) Architecture*. RFC 9334, IETF, 2023.
   <https://www.rfc-editor.org/rfc/rfc9334>
8. Munoz, J. *A SCITT Profile for Pre-Execution AI Action Authorization
   Records*. Internet-Draft draft-munoz-scitt-permit-profile-01, 2026.
   <https://datatracker.ietf.org/doc/html/draft-munoz-scitt-permit-profile-01>
9. Emirdag, P. *AI Agent Execution Profile of SCITT*. Internet-Draft
   draft-emirdag-scitt-ai-agent-execution-00, 2026.
   <https://datatracker.ietf.org/doc/html/draft-emirdag-scitt-ai-agent-execution-00>
10. RIPE NCC Staff. “RIPE Atlas: A Global Internet Measurement Network.”
    *The Internet Protocol Journal* 18(3), 2015.
    <https://www-static.ripe.net/static/rnd-ui/atlas/static/page/InternetProtocolJournal-18-3.pdf>
11. Kisteleki, R. “RIPE Atlas Architecture — How We Manage Our Probes.”
    RIPE Labs, 2017.
    <https://labs.ripe.net/author/kistel/ripe-atlas-architecture-how-we-manage-our-probes/>
12. RIPE NCC. “User-defined Measurements.” RIPE Atlas Documentation, accessed
    13 August 2026.
    <https://atlas.ripe.net/docs/getting-started/user-defined-measurements/>
13. RIPE NCC. “Listing and Filtering Measurements.” RIPE Atlas REST API
    Documentation, accessed 13 August 2026.
    <https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/listing-measurements/>
14. Josefsson, S. and Liusvaara, I. *Edwards-Curve Digital Signature Algorithm
    (EdDSA)*. RFC 8032, IETF, 2017.
    <https://www.rfc-editor.org/rfc/rfc8032>
15. Rundgren, A., Jordan, B., and Erdtman, S. *JSON Canonicalization Scheme
    (JCS)*. RFC 8785, IETF, 2020.
    <https://www.rfc-editor.org/rfc/rfc8785>
