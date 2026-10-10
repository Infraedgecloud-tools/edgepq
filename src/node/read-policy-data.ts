/* Node-side reader for the policy tables in rules/data/. The renderers take
   this as data and never read files themselves. */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export async function readPolicyData(rulesDir: string): Promise<{ elb: unknown; apigw: unknown }> {
  const read = async (name: string): Promise<unknown> => JSON.parse(await readFile(join(rulesDir, 'data', name), 'utf8'));
  return { elb: await read('elb-security-policies.json'), apigw: await read('apigw-security-policies.json') };
}

/* The tool version comes from package.json, read here and passed into the report. */
export async function readToolVersion(packageJsonPath: string): Promise<string> {
  return (JSON.parse(await readFile(packageJsonPath, 'utf8')) as { version: string }).version;
}
