# Changelog

All notable changes to EdgePQ. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/). Rule IDs never change
meaning; a rule that needs different semantics gets a new ID.

## [Unreleased]

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
