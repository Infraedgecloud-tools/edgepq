<p align="center"><img src="docs/assets/wordmark.svg" width="420" alt="EdgePQ"></p>

<p align="center">
  <a href="https://github.com/infraedgecloud-tools/edgepq/releases/latest"><img src="https://img.shields.io/github/v/release/infraedgecloud-tools/edgepq?display_name=tag&color=0B2545" alt="Release"></a>
  <a href="https://github.com/infraedgecloud-tools/edgepq/actions/workflows/ci.yml"><img src="https://github.com/infraedgecloud-tools/edgepq/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/@infraedgecloud/edgepq"><img src="https://img.shields.io/npm/v/@infraedgecloud/edgepq?color=1A63B0&label=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-1A63B0" alt="Apache-2.0"></a>
</p>

**EdgePQ says which of your AWS endpoints and keys still rely on classical cryptography,
and what to change.** It reads your Terraform or your account, names the load balancer
listeners, API Gateway domains, CloudFront distributions and KMS keys that negotiate a
key exchange a quantum computer could later break, and gives the one-line fix for each,
with the AWS documentation it rests on.

Traffic recorded today can be decrypted later ("harvest now, decrypt later"). AWS has
shipped hybrid post-quantum key exchange (ML-KEM) on most of its TLS front doors as a
policy setting. Whether it is on is a configuration question, and that is what EdgePQ
answers. Nothing is ever called safe or compliant, and nothing is ever applied.

<p align="center"><img src="docs/assets/demo.svg" width="960" alt="edgepq scan on a Terraform directory: three listeners on classical policies, the policy to set for each, four values that could not be checked offline, three already enabled"></p>

## Try it in a minute

```bash
npx @infraedgecloud/edgepq scan ./terraform
```

Needs Node 20.10 or later. The summary prints to the terminal and the files land in
`./edgepq-out/`:

```
edgepq-out/
  edgepq-findings.json     every finding, with observed values, the fix and dated sources
  edgepq-report.md         the same, readable
  edgepq-report.html       the same, self-contained, no external requests
  edgepq-cbom.cdx.json     CycloneDX 1.6 cryptographic bill of materials
  patches/                 one unified diff per fix, plus edgepq-auto.patch and edgepq-all.patch
```

No account, no upload, no telemetry: `scan` reads files and writes files. The same
scanner runs in a browser as [EdgePQ Check](https://infraedge.org/tools/edgepq-check),
for a paste-and-see answer.

## Install

| | |
|---|---|
| npm | `npm install -g @infraedgecloud/edgepq` |
| One-off | `npx @infraedgecloud/edgepq scan ./terraform` |
| Release tarball | `npm install -g https://github.com/infraedgecloud-tools/edgepq/releases/download/v0.1.0/infraedgecloud-edgepq-0.1.0.tgz` |
| From source | `git clone https://github.com/infraedgecloud-tools/edgepq && cd edgepq && npm ci && node bin/edgepq.js` (Node 22.18 or later runs the TypeScript directly) |

Every release attaches the tarball, its SHA-256 and a
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):

```bash
gh attestation verify infraedgecloud-edgepq-0.1.0.tgz --owner infraedgecloud-tools
```

The npm package is published with provenance from the same workflow.

## Four surfaces, one engine

| Command | Input | Output |
|---|---|---|
| `edgepq scan <dir>` | Terraform HCL | findings, report, CBOM, patches |
| `edgepq scan <plan.json>` | `terraform show -json` plan or state | findings, report, CBOM |
| `edgepq aws` | read-only API calls across accounts and regions | findings, report, CBOM, evidence |
| `edgepq verify <host>` | a few TLS connections | the key exchange the endpoint selects, and whether a hybrid handshake completes |

Exit codes: `scan` and `aws` exit 0, 1 when `--fail-on SEV` is reached by a failed
finding, 2 on bad input or when nothing was found to check. A gate pointed at the wrong
directory must not pass. `verify` exits 0 when the endpoint selects or supports a
hybrid group, 1 when it is classical or TLS 1.2 only, 2 when the answer is inconclusive
or the host could not be reached.

### Scanning Terraform

A directory is read the way Terraform reads it. The `*.tf` files in it are the root
module; each `module` block with a local source (`./modules/alb`) is read under
`module.<name>` with the values the call passes in, and a `var.x` inside a module
resolves to that value, or to the variable's default, which the report lists as an
assumption. A directory under the target that nothing calls is read as a root of its
own, with its path as the address prefix (`modules/alb:aws_lb_listener.https`), so a
repository of modules can be scanned too. Modules from a registry or a remote source
are not read; the report says so.

Anything the engine cannot resolve offline, an expression, a value from a data source,
is *could not check*, never a pass and never a fail. The report lists every such item.

```bash
edgepq scan ./terraform --fail-on high        # exit 1 if a high or critical finding failed
terraform show -json tfplan > plan.json && edgepq scan plan.json
```

### Scanning an account

Read-only, and every IAM action is named one by one: apply
[`terraform/edgepq-readonly-role/`](terraform/edgepq-readonly-role/) in each account to
be scanned. The role reads listener, distribution, API Gateway domain and API, KMS key,
ACM certificate and Private CA metadata, and the 90-day CloudTrail event history for the
client sample; it reads no function code, no environment variables and no secrets.

```bash
edgepq aws                                                   # the account your credentials belong to, every enabled region
edgepq aws --regions eu-west-2,us-east-1
edgepq aws --accounts 222222222222,333333333333 --role-name edgepq-readonly --external-id ...
edgepq aws --org --role-name edgepq-readonly                  # every active account in the organization
```

The CloudTrail sample (`--cloudtrail-sample N`, default 200 per service and region, `0`
to disable) reads KMS and Secrets Manager calls and reports which clients negotiated
classical key exchange, by user agent. `--org` additionally needs
`organizations:ListAccounts` on the principal running the scan.

### Verifying an endpoint

```bash
edgepq verify api.example.com
edgepq verify 203.0.113.10:8443 --servername api.example.com --json
```

Sends a browser-like TLS 1.3 ClientHello and reports the group the server put in its
ServerHello, then a hybrid-only offer, then one real handshake per group through Node's
own TLS stack. The verdict is one of `hybrid_selected`,
`hybrid_supported_not_preferred`, `classical_only`, `tls_1_2_only`, `inconclusive`,
with the evidence beside it. The real handshakes need Node 22.20 or later (the OpenSSL
that can negotiate the hybrid groups); on an older Node they are reported as not
testable and the verdict rests on the hellos, which the output says.

## What it checks

`edgepq rules` prints every rule with its sources and the date each was verified. In
short:

- **Key exchange (harvest now, decrypt later), ranked first.** ALB and NLB listener
  policies; API Gateway custom domains and REST API endpoints; CloudFront viewer policy;
  KMS RSA encryption keys and ECDH key agreement.
- **Clients.** Which SDKs actually negotiate ML-KEM with KMS and Secrets Manager, from
  CloudTrail (`aws` only).
- **Signatures, ranked after.** KMS signing keys; Private CA key algorithms.
- **Inventory.** ACM certificates and everything above, in the CBOM.

What it does not look at is printed at the top of every report: CloudFront to origin,
Transfer Family, Classic Load Balancers, HTTP API default endpoints, KMS replica and
external keys, application code, other clouds.

Rules are YAML under [`rules/`](rules/), one file each, with a failing and a passing
fixture under `test/fixtures/rules/`. The findings JSON is described by
[`schema/findings.schema.json`](schema/findings.schema.json).

## Developing

```bash
npm ci
npm run check            # typecheck + every test; no network
EDGEPQ_NET=1 npm test    # also a probe test against a live AWS endpoint
npm run build            # dist/ (the package) and dist/web/ (the browser bundle)
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers adding a rule, [SECURITY.md](SECURITY.md) what
counts as a security issue, [CHANGELOG.md](CHANGELOG.md) what changed.

## Licence

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [TRADEMARKS.md](TRADEMARKS.md).
EdgePQ is built by [InfraEdge](https://infraedge.org).
