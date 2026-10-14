# Rules

One YAML file per rule. The loader in `src/engine/rules.ts` is the schema: a
rule that fails validation fails CI with the field named.

Required: `id` (`AREA-KIND-001`), `version` (a whole number from 1; bump it when the
predicates, defaults, fix, severity or category change, not for wording), `title`, `resource_types`, `category`
(`key-exchange | client | signature | inventory`), `severity`, `pass_when`,
`message.{fail,pass,unknown}`, and `sources[]` with `url` and `verified` date.

Optional: `applies_when`, `unknown_when`, `defaults` (what AWS uses when the attribute is
absent), `fix`, `tables` (named mappings a fix can use through `value_from`),
`fail_as: not_configurable` (nothing in the resource can pass; the finding is
reported apart from failures someone can fix) and `pass_as: on_by_default` (the
service does the work with nothing to set; the finding is reported apart from
settings someone enabled).

Predicates: `all`, `any`, `not`, and leaf tests `eq`, `in`, `matches`,
`present`, `absent` on dotted attribute paths. `[n]` indexes a block list,
`[*]` means any element. Anything the engine cannot resolve offline yields
`unknown`, never `fail`.

Every rule has a failing and a passing fixture under `test/fixtures/rules/<RULE-ID>/`;
a test asserts both exist and evaluate as named.
