/* SARIF 2.1.0, for GitHub code scanning and any other consumer of the format.

   One run, one rule per rule that ran, one result per finding that needs a
   person: failures and not-configurable outcomes as `fail`, could-not-check
   as `review`. Passes are left out; the findings JSON has them, and a code
   scanning view that lists every listener that is fine is a view nobody
   reads. The fingerprint goes in partialFingerprints, so an alert survives a
   file move. Browser-safe: locations come in from the caller, who has the
   files; the renderer never reads one.

   Schema: https://json.schemastore.org/sarif-2.1.0.json (vendored under
   test/schemas for the test). */
import type { Finding, Severity } from '../engine/types.ts';
import type { ScanReport } from './types.ts';

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFORMATION_URI = 'https://github.com/infraedgecloud-tools/edgepq';

/* Where a finding is, when the caller knows. `uri` is the path a consumer
   should show (relative to the repository root when the scan ran inside
   one); `line` is the first line of the resource block. */
export type SarifLocations = {
  uri?: (file: string) => string;
  line?: (file: string, finding: Finding) => number | undefined;
};

type Json = { [k: string]: unknown };

/* GitHub maps error/warning/note to its own severities; critical and high
   are errors, medium a warning, low and info notes. */
const LEVEL: { [s in Severity]: 'error' | 'warning' | 'note' } = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

function location(f: Finding, locs: SarifLocations, report: ScanReport): Json[] {
  const o = f.resource.origin;
  if (o.kind === 'hcl') {
    const line = locs.line?.(o.file, f);
    const physical: Json = { artifactLocation: { uri: locs.uri ? locs.uri(o.file) : o.file, uriBaseId: 'ROOT' } };
    if (line !== undefined) physical.region = { startLine: line };
    return [{ physicalLocation: physical, logicalLocations: [{ fullyQualifiedName: f.resource.address, kind: 'resource' }] }];
  }
  if (o.kind === 'plan') {
    const file = report.input.kind === 'plan' || report.input.kind === 'state' ? report.input.file : undefined;
    return [{
      ...(file ? { physicalLocation: { artifactLocation: { uri: locs.uri ? locs.uri(file) : file, uriBaseId: 'ROOT' } } } : {}),
      logicalLocations: [{ fullyQualifiedName: f.resource.address, kind: 'resource' }],
    }];
  }
  return [{ logicalLocations: [{ fullyQualifiedName: o.arn ?? f.resource.address, kind: 'resource', ...(o.arn ? { name: f.resource.address } : {}) }] }];
}

function fixText(f: Finding): string | undefined {
  const fix = f.fix;
  if (!fix) return undefined;
  if (fix.kind === 'guidance') return fix.note;
  const lines = [`${fix.attr} = ${JSON.stringify(fix.value)}`, ...Object.entries(fix.also_set ?? {}).map(([k, v]) => `${k} = ${JSON.stringify(v)}`)];
  return `${lines.join('\n')}\nSafety: ${fix.safety}.${fix.note ? ' ' + fix.note : ''}`;
}

export function renderSarif(report: ScanReport, locs: SarifLocations = {}): string {
  const ruleIndex = new Map(report.rules.map((r, i) => [r.id, i]));
  const rules = report.rules.map((r) => ({
    id: r.id,
    name: r.id.replace(/-/g, ''),
    shortDescription: { text: r.title },
    fullDescription: { text: r.title },
    ...(r.sources[0] ? { helpUri: r.sources[0].url } : {}),
    help: { text: r.sources.map((s) => `${s.url} (verified ${s.verified})`).join('\n') },
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: { category: r.category, severity: r.severity, version: r.version, tags: ['security', 'post-quantum', r.category] },
  }));
  const results = report.findings
    .filter((f) => f.status === 'fail' || f.status === 'not_configurable' || f.status === 'unknown')
    .map((f) => {
      const fix = fixText(f);
      const result: Json = {
        ruleId: f.rule.id,
        ruleIndex: ruleIndex.get(f.rule.id),
        kind: f.status === 'unknown' ? 'review' : 'fail',
        level: f.status === 'unknown' ? 'note' : LEVEL[f.rule.severity],
        message: { text: fix ? `${f.message}\n\nFix:\n${fix}` : f.message },
        locations: location(f, locs, report),
        partialFingerprints: { 'edgepq/v1': f.fingerprint },
        properties: { status: f.status, address: f.resource.address, resource_type: f.resource.type, rule_version: f.rule.version },
      };
      return result;
    });
  const doc = {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'edgepq', version: report.tool.version, informationUri: INFORMATION_URI, rules } },
      originalUriBaseIds: { ROOT: { description: { text: 'The directory or file passed to edgepq scan, or the repository root when the scan ran inside one.' } } },
      invocations: [{ executionSuccessful: true, endTimeUtc: report.generated_at }],
      results,
    }],
  };
  return JSON.stringify(doc, null, 2) + '\n';
}
