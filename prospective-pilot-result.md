# Prospective pilot result

**Executed:** 2026-08-13
**Host:** `zeus1` only
**Final verifier verdict:** `ALLOW`
**Claim class:** bounded observation

## Ordering trace

| Time (UTC) | Event | Evidence |
|---|---|---|
| 17:44:30 | Experiment Permit signed | `prospective/precommit/permit.json` |
| before 17:49 | Exact request and empty-ID precommit publicly deployed | site commit `de25da7`; public precommit state `PERMITTED_NOT_EXECUTED` |
| 17:49:52 | First session-auth attempt rejected with HTTP 403 before creation | `prospective/execution/attempt-01-rejected.json` |
| 17:50:05 | Same body accepted after adding RIPE-required transport header | `prospective/execution/creation-response.json` |
| 17:51:50 | Python collector captured 8 metadata objects and 32 result rows | private Zeus1 lab capture; allow-listed `prospective/capture-manifest.json` |
| 17:52:21 | Chrome-CDP code path replayed the 8 public result sets | `prospective/witness/browser-observation.json` |
| after 17:52 | Collector and witness signatures verified; closure `ALLOW` | `prospective/closure.json` and `prospective/witness/witness.json` |

The required `X-Requested-With: XMLHttpRequest` header belongs to session
transport and did not alter the 3,340-byte JSON body.  The first attempt
returned no measurement IDs; no retry was made until the explicit 403 proved
that no platform object had been created.

## Frozen binding

- Exact canonical request SHA-256:
  `ae3c95459fba6e8a3fb1120aeecf47529a214aaa0bfacceb45ee0a7d051c91ad`
- Permit ID: `tyche-fptp-2026-08-13-p01`
- Target: `tyche.institute`
- Requested probes: `28`, `81`, `6349`, `6569`
- Definitions: ping, traceroute, DNS, and TLS-certificate retrieval over IPv4
  and IPv6
- One-off and public: true
- Automatic top-up: false
- Maximum declared credits: 1,060
- Balance immediately before accepted action: 391,423

## Platform effect and evidence

RIPE assigned these eight identifiers:

```text
200503603  ping        IPv4
200503604  ping        IPv6
200503606  traceroute  IPv4
200503607  traceroute  IPv6
200503608  DNS         IPv4
200503609  DNS         IPv6
200503610  TLS cert    IPv4
200503611  TLS cert    IPv6
```

All four requested probes were scheduled for every definition.  Each
definition returned four rows, for 32/32 scheduled rows and 32/32 narrow
successes.  RIPE metadata reports 848 credits from those rows: 48 for ping, 480
for traceroute, 160 for DNS, and 160 for TLS certificate retrieval.

Raw result rows are retained in the private Zeus1 lab directory and remain
fetchable from the linked public RIPE APIs.  The research repository publishes
only their filenames, sizes, SHA-256 digests, aggregate source IDs, and bounded
closure, avoiding an unnecessary second public copy of address-bearing rows.

The authenticated account counter increased by 899 during the broader interval,
but the separate ongoing campaign was also active.  The result-derived 848 is
therefore the pilot attribution; the account-level delta must not be wholly
assigned to this action.

## Verifier result

The prospective verifier passed the Permit signature, exact request digest,
execution host, credit ceiling, eight-ID shape, definition binding, target
binding, scheduled-source subset, result-source binding, observed credit
ceiling, complete source coverage, bounded claim class, and browser-witness
agreement.  No first bad edge was present.

The deterministic replay remains the fault evaluation.  The live pilot is one
clean prospective trace, not a reliability study.

## Infrastructure-separated replay

GitHub Actions run
[`31729489880`](https://github.com/tyche-institute/tyche-institute-site/actions/runs/31729489880)
executed the Node verifier on a GitHub-hosted runner after site commit
`11f76b97a29fd11ae56f2d8b9b9082ef1e6d37da`.  It passed 56 gates against both
the checked-out artifacts and the production URLs, reproducing the request
digest, eight IDs, 32 results, 32 narrow successes, and 848 credits.  This is
technically separate from Zeus1, but the workflow and repository remain under
Tyche administration; it is not an independent audit.

## Performance snapshot

On the recorded Zeus1 environment (Python 3.12.3, `cryptography` 49.0.0), the
witnessed composed verifier's paired-corpus descriptive median was approximately 273 μs per
11.3 KB replay bundle over 2,000 full-corpus passes.  The signed prospective
closure was 10.3 KB and the 17 retained capture JSON files totalled 80.6 KB.
These single-host measurements are not cross-system performance claims.

## Boundaries

- The project and collector keys show possession of local experiment keys, not
  independently verified human identity or legal authority.
- RIPE public API records arrived over TLS but are not RIPE-signed evidence.
- The browser witness uses a different code path and signing key but shares
  Zeus1, Tyche administration, the network, and the RIPE upstream.  It is not
  Byzantine or organisational independence.
- “32/32 narrow successes” is one bounded one-off observation, not proof of
  global/long-term availability, security, legal compliance, membership, or
  LIR status.
