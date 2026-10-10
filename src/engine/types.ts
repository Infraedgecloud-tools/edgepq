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
};

export type FixSafety = 'auto' | 'review' | 'none';

export type Fix =
  | { kind: 'set-attribute'; attr: string; value: string; safety: FixSafety; note?: string }
  | { kind: 'set-attribute'; attr: string; value_from: string; safety: FixSafety; note?: string }
  | { kind: 'guidance'; note: string; safety: 'none' };

export type Rule = {
  id: string;
  title: string;
  resource_types: string[];
  category: Category;
  severity: Severity;
  applies_when?: Predicate;
  pass_when: Predicate;
  /* What AWS uses when the attribute is absent from the configuration. Applied
     before the predicates, so a missing `ssl_policy` is checked as the default
     the API would have chosen. */
  defaults?: { [attr: string]: AttrValue };
  fix?: Fix;
  message: { fail: string; pass: string; unknown: string };
  sources: Source[];
  /* Mapping tables a fix can refer to by name through `value_from`. */
  tables?: { [name: string]: { [from: string]: string } };
};

/* --------------------------------------------------------------- findings */

export type Status = 'fail' | 'pass' | 'unknown' | 'not_applicable';

export type Finding = {
  id: string;
  rule: { id: string; title: string; category: Category; severity: Severity };
  status: Status;
  resource: { type: string; address: string; origin: Origin };
  /* Every attribute the predicates read, with the value they saw. A default
     that was applied is reported as `{ value, defaulted: true }`. */
  observed: { [attr: string]: { value: AttrValue | undefined; defaulted?: true; unknown?: true } };
  message: string;
  fix?: ResolvedFix;
  sources: Source[];
};

export type ResolvedFix =
  | { kind: 'set-attribute'; attr: string; value: string; safety: FixSafety; note?: string }
  | { kind: 'guidance'; note: string; safety: 'none' };
