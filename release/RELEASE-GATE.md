# Release and DOI gate

## Ready

- 21 matched positive/negative pairs plus one clean baseline are generated and
  all 22 authorised controls are accepted by every treatment.
- Five verifier treatments, 448 generated variations, prospective Permit,
  eight RIPE effects, collector closure, browser witness, tests, performance
  snapshot, manuscript, and claim–evidence matrix are versioned.
- No PEM key, private-key marker, or raw address-bearing result row is present
  in the repository artifact.
- Raw capture is retained privately on Zeus1 with a public privacy-minimised
  hash manifest and original RIPE API links.
- Production Observatory and machine-readable artifacts are public.
- GitHub-hosted run `31729489880` passed all 56 gates against both checkout and
  production artifacts; execution is separate from Zeus1 but not
  administratively independent.
- Zenodo metadata is staged in `zenodo-metadata-draft.json`.

## Published release

- Version DOI: <https://doi.org/10.5281/zenodo.21923744>
- Concept DOI: <https://doi.org/10.5281/zenodo.21923743>
- GitHub release:
  <https://github.com/tyche-institute/from-permit-to-packet/releases/tag/v0.1.0>
- Final public-source workflow: PASS, run `31730924963`.
- Zenodo uploaded-file MD5 verification: PASS for four files before publish.
- Deterministic ZIP SHA-256:
  `846c524f58fb340083f2d5ee8d88b2ef0e6090e44d7dab271406ab524fc1d83d`.

## Resolved for v0.1.0

- Code: Apache License 2.0.
- Manuscript, documentation, and public data: CC BY 4.0.
- Creator: Anton Sokolov, ORCID 0000-0003-2452-7096, Tyche Institute.
- Release type: software with a companion research manuscript and dataset.
- Public source: <https://github.com/tyche-institute/from-permit-to-packet>.

## Recommended release contents

- `README.md`, `manuscript-v0.1.md`, `claim-evidence-matrix.md`;
- `src/`, `tests/`, `corpus/`, `results/`;
- prospective precommit, creation response, allow-listed capture manifest,
  signed closure, and witness;
- `SHA256SUMS`, licence files, citation metadata, and release notes.

Do not include private keys or the private raw-capture directory.
