# Private EdgePQ review corrections — 2026-10-15

Owner coordination required before public disclosure or release. The fixtures use
synthetic canaries only. This overlay applies after the public core snapshot;
its passing tests do not retroactively certify the core without the overlay.

## Confirmed findings and corrections

1. Plan/state sensitivity metadata was not an engine boundary. A value marked
   sensitive could reach observed values and messages. Mark sensitive paths
   unknown and remove values before rules, reports and CBOM assembly. Parent,
   nested object and array masks are honoured. Malformed scalar/structured mask
   combinations fail instead of passing. HCL variables explicitly marked
   sensitive remain unresolved even when defaults or local-module inputs are
   available; report evidence does not repeat those values.
2. Unified-diff context copied neighbouring source text. Generated patches now
   use zero context and include only changed literal assignment lines belonging
   to the intended fix. If a changed line has a comment or unrelated source,
   skip it with a reason rather than copying it. File/resource identities that
   cannot be safely represented are refused. Individual and combined patches
   remain useful and pass git's application check. The documented invocation
   becomes `git apply --unidiff-zero <file>`; review line locations and use a
   clean, unchanged checkout before applying, then run Terraform fmt/plan.
3. JSON/HCL parser errors could repeat malformed source excerpts. Input errors
   now retain the file and generic parse failure, omitting raw parser details.
   This deliberately reduces error detail to protect source material.
4. Human output allowed terminal controls and Markdown injection through
   identifiers. CLI output strips control bytes, and Markdown escapes untrusted
   headings/messages/values/coverage text. Machine JSON continues to encode
   values through JSON.stringify; HTML already escapes external text.

## Regression evidence

`test/security-regressions.test.ts` uses `EDGE_SYNTHETIC_CANARY_482716`, never a
real secret. It checks all written JSON/Markdown/HTML/SARIF/CBOM outputs plus
stdout/stderr for sensitive plan/state input, omitted neighbour context in
individual/combined patches, rejection of mixed comment lines, sanitised JSON
and HCL errors, inert terminal/Markdown input, and sensitive HCL default/input
handling. Existing patch fixture tests apply every generated patch and combined
patch with `git apply --unidiff-zero`; outcomes are re-evaluated through the
engine. Existing browser/Node parity fixtures run against the same adapter code.

These corrections do not promise complete secret recognition. An arbitrary
unmarked literal deliberately supplied as a rule-observed value can appear in
reports. Terraform sensitivity masks and sensitive HCL declarations are the
explicit boundaries. Raw input files themselves are not modified. Credentials
and account identifiers in AWS evidence still require owner review before
sharing. Same-user filesystem races, exhaustive hostile parser work, broad
redaction fuzzing, full browser network instrumentation and every supported OS
remain incomplete release gates.

## Integration

Apply `public-core.patch` to base
`ed6457a634fb625c4067a53d2ad9fc78b3df8ff6`, then
`security-overlay.patch`, in an isolated checkout. Run `npm ci`, `npm run check`,
`npm pack --pack-destination <scratch>`, install the tarball outside the checkout,
and run the installed CLI consumer checks as described in the public evidence.
No public release/tag/npm publication or cloud mutation is authorised by this
file. Public core stays draft until coordinated security integration is complete.

Final local evidence: full source `npm run check` has 209 tests (208 pass, one
opt-in network skip). Independent reviewer repeated that full suite and 24
focused cases, and verified a stalled loopback STS response aborts with a 100 ms
budget in 157 ms. No live AWS account was used. A packed full-overlay artifact
installed outside source passed 14 consumer/security tests with CLI child
processes on Node 24.19.0 and Node 20.20.2. The test harness itself ran on Node
24 for native TypeScript stripping. These artifact checks supplement the public
core's separate 204-test/9-consumer-test evidence; they are not interchangeable.
