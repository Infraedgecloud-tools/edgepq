# Contributing to EdgePQ

Small pull requests are easiest to review. Open an issue first for anything large.

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by` line. Add it with:

```sh
git commit -s
```

The sign-off certifies the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change or have the right to submit it under the project's licence (Apache-2.0). Use your real name and an email address you control. A pull request with unsigned commits will not be merged.

## Commit messages

Use a conventional prefix (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), imperative mood, under 72 characters.

## Checks to run

```sh
npm ci
npm run check       # typecheck + every test; no network
EDGEPQ_NET=1 npm test   # also the probe test against a live AWS endpoint
```

CI runs the same, then installs the packed tarball on Node 20 and Node 24 and runs the fixtures through it.

Needs Node 22.18 or later to run the TypeScript sources directly. The package that users install is compiled JavaScript (`npm run build`) and runs on Node 20.10 or later.

## Adding a rule

A rule is data. `rules/README.md` documents the schema and the predicates.

1. Add `rules/<AREA>-<KIND>-<NNN>.yaml`. Every `sources[]` entry links the AWS documentation page the rule rests on and carries the date you verified it.
2. Add `test/fixtures/rules/<RULE-ID>/fail.tf` and `pass.tf`. The rule test evaluates both through the real HCL parser and asserts the named outcome.
3. If the rule needs a table (a policy name to its key exchange), put it under `rules/data/` and say where it came from. `scripts/extract-elb-policies.py` generates the ELB table from the AWS documentation.
4. Write the three messages so that a reader who does not know the rule can act on them. Nothing is ever called safe or compliant.

A rule can only say `fail` for what it can see. Anything the engine cannot resolve offline, a value from a remote module or an expression, is `unknown`, never `fail`.

## Wrong findings

A rule that fails a ready resource or passes one that is not is a bug. Open an issue with the wrong-finding template and attach a redacted fixture. A fix comes with a regression fixture. A rule that calls something ready when it is not is the more serious kind; see SECURITY.md.

## Evidence carries identifiers

Reports, the CBOM and `edgepq aws` evidence carry resource names, ARNs and account IDs. Redact them before attaching anything to an issue or pull request. Fixtures use the documentation's example account IDs only.

## Conduct

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
