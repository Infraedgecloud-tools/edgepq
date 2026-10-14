/* ============================================================================
   Are the policy tables under rules/data still what AWS publishes?

   Fetches the pages the tables were built from and compares the policy
   names on them with the names in the data. Nothing is written: a
   difference is printed and the exit code is 1, so the weekly workflow can
   open an issue and a person can regenerate the table (ELB: see
   scripts/extract-elb-policies.py; API Gateway: rules/data/README.md).

   Usage: node --experimental-strip-types scripts/check-policy-data.ts
   ========================================================================= */
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const UA = 'edgepq-policy-data-check (+https://github.com/infraedgecloud-tools/edgepq)';

type Elb = { sources: { url: string }[]; policies: { [name: string]: unknown } };
type Apigw = { sources: { url: string }[]; policies: { [name: string]: { accepted_by_api?: boolean } } };

async function page(url: string): Promise<string> {
  const res = await fetch(url, { headers: { 'user-agent': UA, accept: 'text/html' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
}

/* Names as they appear in running text and tables. A name that ends in a
   hyphen is a sentence fragment ("ELBSecurityPolicy-TLS-..."), not a policy. */
const names = (html: string, re: RegExp) => new Set([...html.matchAll(re)].map((m) => m[0]).filter((n) => /[A-Za-z0-9]$/.test(n)));

function compare(label: string, onPages: Set<string>, inData: Set<string>): string[] {
  const problems: string[] = [];
  for (const n of [...onPages].sort()) if (!inData.has(n)) problems.push(`${label}: ${n} is on the AWS page and not in the data`);
  for (const n of [...inData].sort()) if (!onPages.has(n)) problems.push(`${label}: ${n} is in the data and no longer on the AWS page`);
  return problems;
}

export async function checkPolicyData(): Promise<string[]> {
  const elb = JSON.parse(await readFile(`${root}rules/data/elb-security-policies.json`, 'utf8')) as Elb;
  const apigw = JSON.parse(await readFile(`${root}rules/data/apigw-security-policies.json`, 'utf8')) as Apigw;
  const problems: string[] = [];

  const elbPages = await Promise.all(elb.sources.map((s) => page(s.url)));
  const elbNames = new Set<string>();
  for (const html of elbPages) for (const n of names(html, /ELBSecurityPolicy-[A-Za-z0-9-]+/g)) elbNames.add(n);
  problems.push(...compare('ELB', elbNames, new Set(Object.keys(elb.policies))));

  /* The developer guide and the API reference each list the names; the data
     keeps both spellings of the FIPS PQ policy and says which one the API
     accepts, so each page is compared with the names it is expected to carry. */
  const [guide, apiRef] = await Promise.all(apigw.sources.map((s) => page(s.url)));
  const re = /SecurityPolicy_[A-Z0-9_]+|\bTLS_1_[0-9]\b/g;
  const onGuide = names(guide as string, re);
  const onApi = names(apiRef as string, re);
  const all = Object.keys(apigw.policies);
  const acceptedByApi = new Set(all.filter((n) => apigw.policies[n]?.accepted_by_api !== false));
  problems.push(...compare('API Gateway API reference', onApi, acceptedByApi));
  /* The guide may spell a name differently from the API; a name on the guide
     the data does not know at all is the signal. */
  for (const n of [...onGuide].sort()) if (!all.includes(n)) problems.push(`API Gateway developer guide: ${n} is on the AWS page and not in the data`);
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const problems = await checkPolicyData();
  if (problems.length) {
    console.error(problems.join('\n'));
    console.error(`\n${problems.length} difference(s). Regenerate the table, re-verify the rule sources, bump the rule versions that change.`);
    process.exit(1);
  }
  console.log('rules/data agrees with the AWS pages');
}
