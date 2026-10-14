# Changelog

All notable changes to EdgePQ. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/). Rule IDs never change
meaning; a rule that needs different semantics gets a new ID.

## [Unreleased]

### Added
- `edgepq-findings.sarif` beside the other outputs: SARIF 2.1.0 with one result per failed,
  not-configurable or could-not-check finding, located on the resource block, for
  `github/codeql-action/upload-sarif` and other consumers of the format.
- Every finding carries a `fingerprint` (FNV-1a 64 over rule id, resource type and
  address) that is the same across runs and across a file move; the SARIF results use it
  as their partial fingerprint. The findings schema requires it.
- `scripts/check-policy-data.ts` fetches the AWS pages the tables under `rules/data` were
  read from and compares the policy names; a weekly workflow runs it and opens an issue
  on a difference. `test/rules.test.ts` holds the policy lists in the API Gateway rules
  to the data file, as it already did for ELB. Reports list the pages and the dates the
  tables were read under Coverage.
- Every rule carries a `version`, listed by `edgepq rules` and in the reports' rules
  table, and recorded on each finding as `rule.version`. The loader rejects a rule
  without one.

### Changed
- A rule can declare `pass_as: on_by_default` for a pass the service provides with nothing
  to set. CF-KX-001 does: a distribution that requires HTTPS is reported under "On by
  default" rather than "Already enabled", in the summary, the reports and the findings
  JSON (`summary.by_status.on_by_default`, finding status `on_by_default`).
- `edgepq verify` runs a third classical control, P-384, so a server configured for
  that curve alone is not reported as refusing every control.

### Fixed
- APIGW-KX-001 offered `SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09` as the fix for a
  FIPS TLS 1.3-only domain: the developer guide's spelling, which the API rejects. The fix
  is now `SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09`. APIGW-KX-003 and APIGW-KX-004 had no
  mapping at all for the two TLS 1.3-only policies and offered "choose a target by hand";
  they map as the domain rule does. All three rules are at version 2.
- A patch to a file inside a called module is marked review, never auto, and its note
  names the module and says every caller takes the change; the combined auto patch
  leaves it out.
- The disagreement note in `edgepq verify` (raw hello selected a group that every Node
  control then refused) compared IANA group names with OpenSSL ones and never fired.
- Usage errors name the option that went wrong (`unknown option --outdir`, `--out needs a
  value`) instead of printing Node's `parseArgs` text.

## [0.1.0] - 2026-10-14

The first release under its own repository and the first published package. EdgePQ was
built and reviewed inside [karshee/Infraedge](https://github.com/karshee/Infraedge) from
7 to 14 October 2026; that history is carried over.

### Added
- `edgepq scan <dir | plan.json | state.json>`: sixteen rules over ALB and NLB listeners,
  API Gateway domains and endpoints, CloudFront distributions, KMS keys, Private CA and
  ACM, with findings JSON, Markdown and self-contained HTML reports, a CycloneDX 1.6 CBOM
  and unified-diff patches that are never applied.
- `edgepq aws`: the same rules over a live account or organization through read-only
  calls, with the IAM role under `terraform/edgepq-readonly-role/` and a CloudTrail
  sample of which clients negotiate classical key exchange.
- `edgepq verify <host>`: the key exchange an endpoint selects, from hand-built
  ClientHellos and real handshakes, with a verdict and the evidence beside it.
- A directory is read as Terraform reads it: local module calls under `module.<name>`
  with their inputs, variable defaults listed as assumptions, uncalled directories as
  roots of their own.
- The browser bundle (`dist/web/edgepq.js`) that runs the scanner in a page with no
  upload; InfraEdge serves it as EdgePQ Check.
- The findings schema, `schema/findings.schema.json`, published at its `$id`.
- A compiled package: `npm install @infraedgecloud/edgepq` runs on Node 20.10 or later;
  `verify` needs Node 22.20 or later for the hybrid handshakes and says so otherwise.

[Unreleased]: https://github.com/infraedgecloud-tools/edgepq/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/infraedgecloud-tools/edgepq/releases/tag/v0.1.0
