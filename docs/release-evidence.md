# EdgePQ candidate evidence — 2026-10-15

This is a bounded hardening candidate, not a release approval or a complete audit.
Base: `Infraedgecloud-tools/edgepq` main `ed6457a634fb625c4067a53d2ad9fc78b3df8ff6`.
All 192 source blobs were fetched through the GitHub connector at that immutable
ref. Unchanged files were checked against their Git blob SHA. No repository code
was executed to interpret Terraform inputs.

## Confirmed defects and candidate changes

| Surface | Before | Candidate |
|---|---|---|
| `src/aws/scan.ts` | Enabled regions from the first account reused for later accounts | Independently discover each account; explicit regions remain explicit; sorted union plus per-scope ledger |
| `src/cli/main.ts` | Zero findings with denied collection exits 0 | Separate complete/partial/failed collection status; default strict coverage exits 2; explicit advisory accepts partial only |
| `src/cli/write.ts` | Successful rescan leaves old patches | Fresh staged owned directory replaces prior outputs; stale patches disappear; unowned content blocks replacement |
| `src/probe/` | Placeholder selection could succeed without real exchange; mixed transient failures could become classical | Real hybrid completion required; transient uncertainty retained; preference unknown named explicitly; certificate authentication separate |
| `src/adapters/plan.ts` | Malformed entries/actions/masks could be ignored | Require format on recognised inputs; reject unsupported major formats, incomplete/errored plans, invalid actions/masks and wrong providers for AWS resource names |
| `src/aws/` | SDK and pagination run budgets not explicit | Three attempts; connect/request/socket limits; run deadline with cancellation; account/region/scope/page/resource caps and repeated-token detection |

The AWS and stale-patch regressions were executed against the original functions
and failed as expected, then passed with the candidate. A loopback HTTP endpoint
with synthetic credentials exercises the actual CLI: all denied fails both
policies, partial requires advisory, complete empty succeeds, and a slow service
is cancelled. These are not live-account tests.

## Executed verification

Environment: Linux 6.18.44 x86_64, Intel Xeon Platinum 8573C; 8 CPU/8 GiB cgroup
budget (9 vCPU visible). Node 24.19.0, npm 11.9.0, lockfile installation.
`npm ci --offline --ignore-scripts` initially failed because yaml was not cached;
normal `npm ci --ignore-scripts` succeeded without escalation.

- Untouched base `npm run check`: 182 tests, 181 pass, 1 explicit opt-in network
  skip, 0 failures.
- Public candidate `npm run check`: 204 tests, 203 pass, 1 opt-in network skip,
  0 failures. Includes pinned JSON, SARIF 2.1.0 and CycloneDX 1.6 schema validation,
  deterministic browser builds and shared fixture engine parity.
- `npm run build` and `npm pack`: succeed. Build includes JavaScript CLI and
  local browser JS/WASM assets. Published package version remains 0.1.0 solely
  for local candidate testing; no tag or package was published.
- Packed tarball installed with `--ignore-scripts --no-audit --no-fund` in a
  fresh `/tmp` consumer directory outside the checkout. `EDGEPQ_BIN=<installed
  bin> node --test --experimental-strip-types test/cli.test.ts test/aws-cli.test.ts`:
  9/9 pass on Node 24.19.0. The same test harness running child CLI processes via
  `EDGEPQ_NODE=<Node 20.20.2>`: 9/9 pass. Includes help/usage, version through
  existing smoke, rule listing, normal/failing/empty/malformed input,
  machine-readable output, ownership collisions, fail-to-pass rescan and AWS
  coverage/cancellation policies. This does not certify every Node 20 minor.

The existing schema validator emits warnings for unregistered CycloneDX IRI/IDN
formats. Structural validation runs, but those formats are not separately
certified. Network was not denied at the OS layer; tests use local fixtures and
loopback endpoints. Opt-in live TLS/AWS tests were not run.

## Installation availability

| Channel | Evidence | Status |
|---|---|---|
| GitHub v0.1.0 tarball | Maintainer inspection downloaded release asset, verified SHA256SUMS, installed and ran help/version on Linux Node 24.19.0 | Released, old behaviour |
| Named npm registry package | `npm view @infraedgecloud/edgepq version dist.tarball --json` returned E404 on 2026-10-15 | Unavailable in this inspection; publication pending |
| Candidate tarball | Built locally; clean consumer tests on Node 20.20.2 and 24.19.0 | Tested locally, unpublished |
| Windows/macOS and remote CI | Workflow defines Linux runners; no new remote matrix result yet | Pending |
| Provenance/signatures | Workflow requests attestation; verification not executed | Pending independent verification |

The repository's release workflow is configuration evidence, not proof of npm
publication. This candidate changes default CI coverage behaviour and output
ownership; choose the next version deliberately (a pre-1.0 minor is appropriate),
update changelog/version together and rerun consumer checks before release.

## Small-fixture measurement

Method: fresh installed Node 24 CLI process per run, offline local
`test/fixtures/terraform/basic` (4 resources, one 2267-byte HCL file), outputs to
fresh empty directories outside the checkout. Wall clock via monotonic Python
clock, child peak RSS from `os.wait4` on Linux. Three runs:

| Run | Wall seconds | Peak RSS KiB | Exit |
|---|---:|---:|---:|
| 1 | 0.752 | 203828 | 0 |
| 2 | 0.529 | 212980 | 0 |
| 3 | 0.786 | 209152 | 0 |

WASM/parser startup dominates this tiny case. These numbers are not a large
repository capacity claim. Monorepo, large, macOS and Windows measurements remain
pending.

## Threat model and bounded scope

Inputs include untrusted Terraform/JSON, module paths, endpoint responses,
identifiers and output locations. The candidate bounds local file count/bytes
and directory/value depth; rejects input/output symlinks; stages owned output;
never executes scanned repository scripts; and puts finite deadlines, retries
and page caps on AWS/TLS work. Outputs and evidence can carry identifiers; review
before sharing. Output ownership protects against accidental collisions, not a
hostile same-user process racing the filesystem. A crash can leave a missing
output path plus staging/backup/lock files: follow README recovery guidance.
Unprivileged unwritable-path testing and kill-at-each-rename fault injection are
not complete; current tests cover file-as-parent failure and a simulated stale
lock while preserving previous reports.

Reviewed: orchestration, output writes, plan/state validation, input traversal,
probe decisions/deadlines/authentication, package contents and existing render/
schema/parity suites. Not fully reviewed: all HCL expression/module instance
semantics; every AWS rule against current primary documentation; sampled
CloudTrail representativeness/window metadata; IAM role minimisation and all
service pagination edge cases; every default credential-provider startup path;
full browser page network instrumentation/accessibility; dependency/workflow/
secret scans and broad maintenance limits. Further security review is tracked
privately with the owner; this draft is not cleared for release until that work
is integrated and independently checked.

## Owner release gates

1. Complete private security review and integrate reviewed corrections before
   publishing this candidate. Keep public PR draft while that dependency remains.
2. Review output/coverage contract and version bump; finish the pending matrix,
   interruption, browser and rule-source checks above.
3. Rebuild, inspect payload, install fresh artifacts, validate checksums and
   provenance against the expected repository/workflow/ref, and confirm registry
   availability independently.
4. Owner decides merge/tag/package publication. No merge, tag, publish, deployment
   or cloud mutation was performed in preparing this candidate.
