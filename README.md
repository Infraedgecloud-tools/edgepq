# EdgePQ

Post-quantum readiness checks for AWS estates. One rules engine, four
surfaces:

| Command | Input | Output |
|---|---|---|
| `edgepq scan <dir>` | Terraform HCL | findings (JSON), report (Markdown + HTML), CBOM (CycloneDX 1.6), patches |
| `edgepq scan <plan.json>` | `terraform show -json` plan or state | findings, report, CBOM |
| `edgepq aws` | read-only API calls across accounts and regions | findings, report, CBOM, evidence |
| `edgepq verify <host>` | one TLS handshake | the key exchange the endpoint actually selected |

The reports say what is enabled, what is not, what could not be checked, and
what the tool does not look at. Nothing is ever called safe or compliant.
Nothing is ever applied: patches are unified diffs for a person to review.

## Run it in five minutes

Needs Node 22.18 or later (`node -v`); `verify` needs 22.20 or later, which
bundles the OpenSSL that can negotiate the hybrid groups.

The repository is private while publishing is decided, so you will have
received the `edgepq/` directory itself. From inside it:

```bash
npm ci
node bin/edgepq.js scan path/to/your/terraform
```

The summary prints to the terminal and the files land in `./edgepq-out/`:

```
edgepq-out/
  edgepq-findings.json     every finding, with observed values, the fix and dated sources
  edgepq-report.md         the same, readable
  edgepq-report.html       the same, self-contained, no external requests
  edgepq-cbom.cdx.json     CycloneDX 1.6 cryptographic bill of materials
  patches/                 one unified diff per fix, plus edgepq-auto.patch and edgepq-all.patch
```

`--fail-on high` makes the exit code 1 when a failed finding is high or
critical, for CI. `--out DIR` changes the output directory.

Try it on the fixtures first: `node bin/edgepq.js scan test/fixtures/rules/ELB-KX-001`.

## What it checks

`node bin/edgepq.js rules` prints every rule with its sources and the date
each was verified. In short, as of 10 October 2026:

- **Key exchange (harvest now, decrypt later), ranked first.** ALB and NLB
  listener policies; API Gateway custom domains and REST API endpoints;
  CloudFront viewer policy; KMS RSA encryption keys and ECDH key agreement.
- **Clients.** Which SDKs actually negotiate ML-KEM with KMS and Secrets
  Manager, from CloudTrail (AWS scan only).
- **Signatures, ranked after.** KMS signing keys; Private CA key algorithms.
- **Inventory.** ACM certificates and everything above, in the CBOM.

Every rule has a failing and a passing fixture under `test/fixtures/rules/`
and a test that evaluates both through the real HCL parser.

What it does not look at is printed at the top of every report.

## Scanning an AWS account

Read-only. Apply `terraform/edgepq-readonly-role/` in each account to be
scanned (every IAM action is named individually; see its README). The role
reads listener, distribution, API Gateway domain and API, KMS key, ACM
certificate and Private CA metadata, and the 90-day CloudTrail event
history for the client sample (those events carry the calling identity,
source IP and user agent, and the report prints the user agents of clients
still on classical key exchange); it reads no function code, no environment
variables and no secrets. `--org` additionally needs
`organizations:ListAccounts` on the principal running the scan. Then:

```bash
node bin/edgepq.js aws                                  # the account your credentials belong to, every enabled region
node bin/edgepq.js aws --regions eu-west-2,us-east-1
node bin/edgepq.js aws --accounts 2222,3333 --role-name edgepq-readonly --external-id ...
node bin/edgepq.js aws --org --role-name edgepq-readonly   # every active account in the organization
```

The CloudTrail sample (`--cloudtrail-sample N`, default 200 per service and
region, `0` to disable) reads the 90-day event history for KMS and Secrets
Manager calls and reports which clients negotiated classical key exchange.

## Verifying an endpoint

```bash
node bin/edgepq.js verify api.example.com
node bin/edgepq.js verify 203.0.113.10:8443 --servername api.example.com --json
```

Sends a browser-like TLS 1.3 ClientHello and reports the group the server
put in its ServerHello, then a hybrid-only offer, then handshakes through
Node's own TLS stack as a cross-check. The hand-built hello carries a
placeholder ML-KEM key share (this Node cannot generate a real one), which
servers in use today accept because they choose the group before using the
share; a server that validated the share first would answer with an alert
and the verdict would fall back to the Node handshakes, which use real keys
and are the authoritative evidence. Both are reported. The verdict is one of
`hybrid_selected`, `hybrid_supported_not_preferred`, `classical_only`,
`tls_1_2_only`, `inconclusive`, with the evidence beside it.

## Developing

```bash
npm run check          # typecheck + every test (no network; a probe test against AWS KMS runs with EDGEPQ_NET=1)
```

Rules are YAML under `rules/`; `rules/README.md` documents the schema. The
ELB policy table is generated by `scripts/extract-elb-policies.py` from the
AWS documentation and checked against the rule by a test.

Design and PR sequence: `docs/edgepq/PLAN.md` at the repository root.
