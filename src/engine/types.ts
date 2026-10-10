/* ============================================================================
   EdgePQ engine — the shapes every surface shares.

   Adapters (HCL, plan JSON, AWS) produce Resources. Rules are data. The
   evaluator turns (rules × resources) into Findings. Renderers read Findings.
   Nothing in this file knows where a Resource came from or where a Finding
   is going.
   ========================================================================= */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/* Ranking order. Harvest-now-decrypt-later exposure (key exchange, and the
   clients that negotiate it) always outranks a signature finding, whatever
   the severities say. */
export type Category = 'key-exchange' | 'client' | 'signature' | 'inventory';
export const CATEGORY_ORDER: readonly Category[] = ['key-exchange', 'client', 'signature', 'inventory'];
export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type Origin =
  | { kind: 'hcl'; file: string }
  | { kind: 'plan' }
  | { kind: 'aws'; account: string; region: string; arn?: string };

/* A literal value as an adapter saw it. Nested blocks arrive as arrays of
   objects, which is how hcl2json and plan JSON both encode them. */
export type AttrValue = string | number | boolean | null | AttrValue[] | { [key: string]: AttrValue };

export type Resource = {
  type: string;
  address: string;
  attrs: { [key: string]: AttrValue };
  /* Dotted attribute paths whose value is not known offline: an expression in
     HCL, an `after_unknown` entry in a plan. A rule that reads one of these
     yields `unknown`, never `fail`. */
  unknown: string[];
  origin: Origin;
  /* Attributes Terraform will not change on an existing resource
     (`lifecycle { ignore_changes }`); a patch to one of them is reported as
     needing review, because applying it changes nothing live. */
  ignore_changes?: string[];
};

/* ------------------------------------------------------------ predicates */

export type LeafTest =
  | { attr: string; eq: AttrValue }
  | { attr: string; in: AttrValue[] }
  | { attr: string; matches: string }      /* a regular expression, applied to the string form */
  | { attr: string; present: true }
  | { attr: string; absent: true };

export type Predicate =
  | { all: Predicate[] }
  | { any: Predicate[] }
  | { not: Predicate }
  | LeafTest;

/* ------------------------------------------------------------------ rules */

export type Source = {
  url: string;
  /* The day the page was read and the quote confirmed, YYYY-MM-DD. */
  verified: string;
  quote?: string;
  /* True when `quote` condenses a table or a list rather than copying one
     sentence, so a reader who cannot find the words on the page knows why. */
  paraphrase?: true;
};

export type FixSafety = 'auto' | 'review' | 'none';

export type TableEntry = string | { value: string; safety: FixSafety; note?: string };

/* `also_set` names attributes the fix must add when they are absent, because
   the target value is invalid without them (an enhanced API Gateway policy
   needs an endpoint access mode). Existing values are left alone. */
/* `unless` turns a set-attribute fix into guidance (`unless_note`) when the
   predicate holds: the target value would be rejected or would break
   something else the resource relies on (mutual TLS with an enhanced API
   Gateway policy). The finding still fails; only the fix changes. */
export type Fix =
  | { kind: 'set-attribute'; attr: string; value: string; safety: FixSafety; note?: string; also_set?: { [attr: string]: string }; unless?: Predicate; unless_note?: string }
  | { kind: 'set-attribute'; attr: string; value_from: string; safety: FixSafety; note?: string; also_set?: { [attr: string]: string }; unless?: Predicate; unless_note?: string }
  | { kind: 'guidance'; note: string; safety: 'none' };

export type Rule = {
  id: string;
  title: string;
  resource_types: string[];
  category: Category;
  severity: Severity;
  applies_when?: Predicate;
  /* True means the value is one the rule cannot judge (a policy name AWS does
     not document, a key spec the API would reject): the finding is `unknown`
     with `message.unknown`, never a pass by accident. */
  unknown_when?: Predicate;
  pass_when: Predicate;
  /* Some rules name a configuration nothing in it can change (an edge-optimized
     API Gateway domain has no PQ policy to choose). Their failing outcome is
     reported as `not_configurable`, so a reader does not raise a change request
     that has no change in it. */
  fail_as?: 'not_configurable';
  /* What AWS uses when the attribute is absent from the configuration. Applied
     before the predicates, so a missing `ssl_policy` is checked as the default
     the API would have chosen. */
  defaults?: { [attr: string]: AttrValue };
  fix?: Fix;
  message: { fail: string; pass: string; unknown: string };
  sources: Source[];
  /* Mapping tables a fix can refer to by name through `value_from`. An entry
     may carry its own safety and note, which override the fix's. */
  tables?: { [name: string]: { [from: string]: TableEntry } };
};

/* --------------------------------------------------------------- findings */

export type Status = 'fail' | 'not_configurable' | 'pass' | 'unknown' | 'not_applicable';

export type Finding = {
  id: string;
  rule: { id: string; title: string; category: Category; severity: Severity };
  status: Status;
  resource: { type: string; address: string; origin: Origin; ignore_changes?: string[] };
  /* Every attribute the predicates read, with the value they saw. A default
     that was applied is reported as `{ value, defaulted: true }`. */
  observed: { [attr: string]: { value: AttrValue | undefined; defaulted?: true; unknown?: true } };
  message: string;
  fix?: ResolvedFix;
  sources: Source[];
};

export type ResolvedFix =
  | { kind: 'set-attribute'; attr: string; value: string; safety: FixSafety; note?: string; also_set?: { [attr: string]: string } }
  | { kind: 'guidance'; note: string; safety: 'none' };
