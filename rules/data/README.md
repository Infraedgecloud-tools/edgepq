# Policy tables

Data the rules and the CBOM read. Every file names the AWS pages it was read from and
the date (`sources[].retrieved`), and the report lists those dates under Coverage.

| File | What | How it is made |
|---|---|---|
| `elb-security-policies.json` | every ALB and NLB security policy: protocols, cipher suites, the post-quantum superset for each classical policy | `scripts/extract-elb-policies.py <alb.md> <nlb.md> <date>` from the two pages saved as Markdown |
| `apigw-security-policies.json` | every API Gateway security policy: endpoint types, protocols, the default per endpoint type, which spelling the API accepts | by hand from the developer guide's table and the API reference; twelve rows |

`scripts/check-policy-data.ts` fetches the source pages and compares the policy names
with these files. It runs weekly (`.github/workflows/policy-data.yml`) and opens an issue
when AWS has added, renamed or withdrawn a policy. When it does:

1. Regenerate or edit the table, with the new `retrieved` date.
2. Re-read the rule sources the change touches and update their `verified` dates.
3. Bump `version` on every rule whose lists or tables change; `test/rules.test.ts`
   holds the lists in the rules to the data.
