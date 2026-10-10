# EdgePQ

Post-quantum readiness checks for AWS estates. Scans Terraform (HCL or plan
JSON) and, read-only, AWS accounts; reports what is enabled, what is not, what
could not be checked and what the tool does not cover; writes a CycloneDX CBOM
and Terraform patches it never applies.

Status: under construction. See `docs/edgepq/PLAN.md` at the repository root.

```bash
cd edgepq
npm ci
npm run check      # typecheck + tests
```
