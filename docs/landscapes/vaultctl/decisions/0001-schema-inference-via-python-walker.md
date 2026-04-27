# 0001 — Schema inference via Python walker, not `cue import`

- **Status:** Accepted
- **Date:** 2026-04-27
- **Decision in:** [PR #41](https://github.com/cdds-ab/vaultctl/pull/41)
- **Related:** [#34](https://github.com/cdds-ab/vaultctl/issues/34), [#40](https://github.com/cdds-ab/vaultctl/issues/40)

## Context

`vaultctl schema infer` derives a CUE schema baseline from the current
vault content. The decision was how to implement the YAML-to-CUE-schema
transformation:

1. **Option A — Use the `cue import` subcommand:** shell out to `cue import data.yml`,
   then post-process the resulting CUE to replace concrete values with
   their types.
2. **Option B — Pure-Python walker:** walk the decrypted vault dict
   directly and emit CUE syntax with types in place of values.

The asymmetry is critical: `cue import` produces *concrete data in CUE
syntax*, not a *schema*. A schema is what we want.

```yaml
# Input
username: admin
```

```cue
// `cue import` output (data, not schema)
username: "admin"

// What schema infer must produce
username: string
```

So Option A still needs a value-to-type substitution pass. The bulk of
the work is the substitution pass; running `cue import` first only adds
a subprocess and a parse-and-rewrite step around it.

## Decision

Use Option B — pure-Python walker. Map Python types directly to CUE
types as the dict is traversed.

| Python type | CUE type emitted |
|-------------|------------------|
| `bool` (checked before `int`!) | `bool` |
| `str` | `string` |
| `int` | `int` |
| `float` | `number` |
| `None` | `null` |
| `list[T]` (homogeneous) | `[...T]` |
| `list` (mixed types) | `[...(T1 \| T2 \| ...)]` (sorted disjunction) |
| `dict` | nested struct, recursively |
| anything else | `_` (CUE top type) — surfaces unexpected shapes without crashing |

`_previous` backup keys are excluded; field names with non-identifier
characters get quoted.

## Consequences

**Positive:**

- Self-contained: no extra `cue` subprocess per inference. Schema
  generation works without the `cue` binary on `$PATH` (though
  `validate` still needs it for the round-trip check).
- Testable in pure Python: 11 unit tests run without any external
  dependency. Round-trip tests then exercise the inferred schema
  against `cue vet` to confirm the output is valid CUE.
- Output is deterministic (sorted keys, stable formatting), suitable
  for git-tracking and diffs.

**Negative:**

- We don't get CUE's parser for free. Edge cases like malformed YAML
  surface as Python errors, not CUE errors. Acceptable — `decrypt_vault`
  already raises before the walker runs, and YAML parse errors come
  from `pyyaml`, which is the upstream of vault content anyway.
- If we ever want to consume someone else's CUE input (e.g., a JSON
  Schema imported via `cue import --jsonschema`) and turn that into
  vaultctl's schema shape, we'd need a different code path. Not
  currently a use case — only relevant if vaultctl ever ingests
  external schema definitions.

**Neutral:**

- The walker emits closed schemas (`#VaultFile: { ... }` with no `...`
  at the end). This is intentional: a closed inferred schema means
  adding a new vault key without re-running `infer` (or extending the
  schema by hand) makes `vaultctl validate` fail. That is the value —
  structural changes become deliberate steps.

## Alternatives Considered

- **`cue import` + AST post-processing**: rejected. Adds a subprocess
  hop and a CUE-to-CUE rewrite layer for no extra capability — the
  type-substitution logic is the same effort either way.
- **Native Python CUE binding**: rejected. No production-ready binding
  exists as of April 2026 (`pycue` is alpha and inactive, official
  `cue-py` not released — see [#34](https://github.com/cdds-ab/vaultctl/issues/34)
  for the survey).
- **JSON Schema generation, then `cue import --jsonschema`**: rejected.
  Adds two indirections (Python→JSON Schema→CUE) for no benefit, and
  loses information about CUE-specific constraints (regex, time formats)
  that we may want to add later.

## References

- Implementation: `src/vaultctl/schema.py` — `infer_vault_schema()`,
  `_render_type()`, `_quote_field()`.
- Tests: `tests/test_schema.py` — `test_infer_*` (unit) and
  round-trip tests with the `requires_cue` marker.
- Discussion: PR #41 description and conversation history.
