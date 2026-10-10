# Rules

One YAML file per rule. The loader in `src/engine/rules.ts` is the schema: a
rule that fails validation fails CI with the field named.

Required: `id` (`AREA-KIND-001`), `title`, `resource_types`, `category`
(`key-exchange | client | signature | inventory`), `severity`, `pass_when`,
`message.{fail,pass,unknown}`, and `sources[]` with `url` and `verified` date.

Optional: `applies_when`, `defaults` (what AWS uses when the attribute is
absent), `fix`, `tables` (named mappings a fix can use through `value_from`).

Predicates: `all`, `any`, `not`, and leaf tests `eq`, `in`, `matches`,
`present`, `absent` on dotted attribute paths. `[n]` indexes a block list,
`[*]` means any element. Anything the engine cannot resolve offline yields
`unknown`, never `fail`.

Every rule has a failing and a passing fixture under `test/fixtures/rules/<RULE-ID>/`;
a test asserts both exist and evaluate as named.
