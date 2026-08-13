# Prospective pilot protocol

**Protocol frozen:** 2026-08-13, before the new RIPE Atlas action
**Execution host:** `zeus1` only
**Status at freeze:** no pilot measurement IDs assigned

This protocol covers one small, prospective, public RIPE Atlas pilot.  The
deterministic replay corpus had already been executed before this file was
written and is therefore exploratory; it must not be described as
preregistered.

## Research questions

- **RQ1:** Can a signed, time-bounded Permit be made public before an
  authenticated platform action and then be bound to the exact request bytes?
- **RQ2:** Can the platform-assigned measurement identifiers be bound back to
  the authorised request without widening target, source, definition, cost, or
  execution-host scope?
- **RQ3:** Can captured results support a deliberately narrow claim without
  silently upgrading it to global availability or security?

## Frozen intervention

- Target: `tyche.institute` only.
- Platform: RIPE Atlas.
- Definitions: exactly eight public one-off measurements: ping, traceroute,
  DNS, and TLS-certificate retrieval over IPv4 and IPv6.
- Requested sources: exactly probes `28`, `81`, `6349`, and `6569`, previously
  used by the bounded Tyche pilot; RIPE may schedule fewer.
- Maximum declared credit exposure: `1060` credits.
- `auto_topup`: false for every definition.
- Execution: authenticated browser session reached through local Chrome CDP
  from `zeus1`; no other host is authorised.
- Stop condition: do not submit if the Permit signature fails, the request
  digest differs, the current credit balance is below 1060, any target or
  source differs, any definition is non-public, or auto-topup is enabled.

## Pre-action record

Before submission, publish:

1. canonical API request JSON without authentication material;
2. SHA-256 of those exact canonical bytes;
3. signed Permit containing that digest and the limits above;
4. public experiment key and explicit statement that it is not an identity or
   legal-signature credential; and
5. a public timestamp through the Tyche Institute deployment history.

The action may proceed only after the public URL returns the same digest.

## Outcomes and acceptance criteria

Primary technical success requires all of the following:

1. the authenticated API returns exactly eight distinct measurement IDs;
2. every returned object has target/query `tyche.institute`, the expected
   type/family pair, public one-off state, and no source outside the requested
   set;
3. every captured result row references a probe scheduled by that measurement;
4. every retained file matches the published SHA-256 manifest;
5. the composed verifier returns `ALLOW` for the prospective bundle; and
6. the public claim remains a bounded observation and reports any unscheduled
   or missing source/result rather than imputing success.

Failure is informative and retained.  A partial platform response, unavailable
probe, empty result set, digest mismatch, or verifier `DENY` is not repaired by
changing the frozen Permit after action.

## Analysis

Report descriptive counts only: definitions requested/created, requested/
scheduled sources, returned rows, narrow protocol successes, credits observed,
verification time, evidence bytes, and first bad edge if denied.  No
significance test or population reliability claim is planned for a single
action.

## Threats to validity

- The user instruction exists in an interactive session; the project key is an
  operator/experiment key, not independently verified human authority.
- RIPE API responses are TLS-delivered upstream data, not RIPE-signed evidence.
- The precommit website, collector, and witness remain under Tyche control.
- Previously successful probes are a convenience sample, not geographic or
  network-representative sampling.
- A one-off successful result says nothing about long-term availability.
