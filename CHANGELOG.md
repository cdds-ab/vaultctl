# CHANGELOG


## v1.3.0 (2026-04-28)

### Features

- **schema**: Vaultctl schema sync drift detection (#40 phase 2)
  ([#51](https://github.com/cdds-ab/vaultctl/pull/51),
  [`dca1b4a`](https://github.com/cdds-ab/vaultctl/commit/dca1b4a73a2b22533d45eee82eb6348a62a1c04d))

## Summary

Phase 2 of #40: \`vaultctl schema sync\` detects drift between the vault content and the
  \`.vaultctl/vault.cue\` baseline. Builds directly on the inference foundation that landed in
  #41/v1.2.0 — same walker, just compared against an existing baseline instead of written fresh.

## New Command

\`\`\`bash vaultctl schema sync # diff-only, exit 1 on drift — CI-friendly vaultctl schema sync
  --apply # rewrite the baseline to match the vault \`\`\`

Exit codes: - \`0\` — no drift, baseline matches. - \`1\` — drift detected, or fresh schema written
  with \`--apply\`. - \`2\` — no baseline exists; suggests \`vaultctl schema infer\` to create one.

Sample output on drift:

\`\`\`diff --- /home/.../vault.cue (current) +++ /home/.../vault.cue (inferred) @@ -2,5 +2,6 @@

#VaultFile: { existing_key: string + new_key: int }

Drift detected. Run \`vaultctl schema sync --apply\` to update /home/.../vault.cue. \`\`\`

## Implementation

- \`compute_schema_drift()\` — pure-Python helper that re-infers the schema from the current vault,
  strips both sides' auto-generated header comments (so wording changes in the header don't trigger
  false positives), and returns \`(drifted, current_text, fresh_text)\`. - \`render_schema_diff()\`
  — thin wrapper over \`difflib.unified_diff\` with stable filename labels for readable output. -
  \`@schema_group.command(\"sync\")\` — orchestrates the three exit-code paths.

\`vault.constraints.cue\` is **never** touched. CUE merges it back in at validation time, so
  hand-edited rules (regex constraints, value ranges) survive both \`infer\` and \`sync\`.

## Test Coverage

13 new tests:

- 9 pure-Python unit tests (no cue binary required) covering missing baseline, key add/remove, type
  change, header-only differences ignored, \`_previous\` backup keys excluded from drift, diff
  rendering on add/identical. - 4 CLI integration tests covering: no-drift after \`schema infer\`,
  missing-baseline exit-2, drift detection from a stale baseline, \`--apply\` round-trip (drift →
  apply → no drift).

Total tests: 360 → 373. Coverage stable at 88%.

## Followup

Phase 3 of #40 — schema-aware \`set\` (interactive prompt to extend the baseline when \`set\`
  introduces a new structure). That's UX work on top of what's now in place; ships as a separate PR.

Refs #40.

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v1.2.2 (2026-04-28)

### Bug Fixes

- **release**: Use merge-multiple to flatten artifact downloads
  ([#50](https://github.com/cdds-ab/vaultctl/pull/50),
  [`2f30ca1`](https://github.com/cdds-ab/vaultctl/commit/2f30ca14fa1623174d3d54dce067b87d3a6f31f9))

## Summary

Fixes the latent bug exposed by v1.2.1: the binary publishing step in \`release.yml\` fails because
  of a name collision between artifact directories and their inner files.

## Evidence

\`\`\` mv: cannot overwrite directory './vaultctl-linux-amd64' with

non-directory ##[error]Process completed with exit code 1. \`\`\`

\`actions/download-artifact@v4\` places each artifact at \`binaries/<artifact-name>/<file>\`. Both
  names are \`vaultctl-linux-amd64\`, so \`mv vaultctl-linux-amd64/vaultctl-linux-amd64 .\` tries to
  overwrite the source directory with the file inside it.

This was latent until v1.2.1 — earlier releases all skipped the binary jobs because semantic-release
  re-runs flagged \`released: false\`. v1.2.1 was the first run since my changes that actually
  triggered the publish path, surfacing the bug.

## Fix

\`actions/download-artifact@v4\` ships a \`merge-multiple: true\` flag designed for exactly this
  case — it places artifact files directly into the target dir without per-artifact subdirectories.
  The flatten loop drops out entirely; only the checksum step remains.

## Followup

After this PR merges and a release fires, the next \`vaultctl-X.Y.Z\` release will have the binaries
  attached. v1.2.1 itself stays without binaries unless we manually upload them — open question
  whether to bother. Probably not, since v1.2.1 is the very recent broken-publish release; the next
  bump (1.2.2 from this fix) will land within minutes.

The README's \`curl .../releases/latest/download/vaultctl-linux-amd64\` install command is **broken
  right now** for v1.2.1; merging this PR and waiting for the followup release is the fastest path
  to repair.

Closes #49.

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v1.2.1 (2026-04-28)

### Bug Fixes

- **release**: Install uv inside semantic-release container
  ([#48](https://github.com/cdds-ab/vaultctl/pull/48),
  [`370edd9`](https://github.com/cdds-ab/vaultctl/commit/370edd925b1ee79b2e9c7c0b3fc958b350867545))

## Summary

Fixes the followup-bug from #46: the \`build_command = \"uv lock && git add uv.lock\"\` shipped in
  PR #46 fails because \`python-semantic-release@v9.15.2\` runs in a Docker container that has
  Python+pip but **no uv on PATH**. Both release attempts after #46 and #47 merged returned exit 127
  for that reason.

## Evidence

\`\`\` CalledProcessError: Command '['bash', '-c',

'uv lock && git add uv.lock']' returned non-zero exit status 127. ERROR
  [version.build_distributions] Build command failed with exit code 127 Build failed, aborting
  release \`\`\`

The workflow's \"Add uv to PATH\" step puts \`~/.local/bin\` into \`\$GITHUB_PATH\`, but that
  environment doesn't propagate into the action's container. The container starts fresh with only
  what its image provides.

## Fix

Prepend \`pip install uv\` to the build_command:

\`\`\`toml build_command = "pip install uv && uv lock && git add uv.lock" \`\`\`

\`pip\` is available inside the action's container (it's a Python image). \`pip install uv\` is fast
  (single binary, ~3 seconds) and idempotent if uv is somehow already there. The build_command
  thereafter runs as designed and stages \`uv.lock\` into the release commit.

## Why Not a Separate Workflow Step?

Two reasons:

1. **Atomicity.** Inside \`build_command\`, the lock change lands in the *same* release commit as
  the version bump. A workflow step after the action would need either a force-push (forbidden on
  master) or a second commit per release.

2. **Reuse.** \`build_command\` is already configured for this purpose; we just need it to actually
  find \`uv\`.

## Followup

Until this PR merges and a release commit fires, master stays at 1.2.0 with all post-#39 work
  queued. The next successful release will be a single bump covering #46, #47, and this fix
  together.

Refs #44.

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

- **release**: Keep uv.lock in sync with version bumps
  ([#46](https://github.com/cdds-ab/vaultctl/pull/46),
  [`9fa6570`](https://github.com/cdds-ab/vaultctl/commit/9fa6570e5525bbaa189323d8c5e0e5f171ce964d))

## Summary

Stops the recurring \`uv.lock\` drift that has produced a manual \`chore: sync uv.lock\` commit on
  every PR in the recent CUE strand (#36, #38, #39, #41).

## Root Cause

\`semantic-release\` bumps the version in \`pyproject.toml\` and \`src/vaultctl/__init__.py\` but
  does not touch \`uv.lock\`. After each release, the lockfile records the pre-release version while
  \`pyproject.toml\` records the new one. The next time anyone runs \`uv sync\` (locally, or in CI's
  pre-commit invocation), the lockfile gets bumped and the diff surfaces.

In CI, that surfaces as \`pre-commit/action@v3.0.1\` exiting 1 — \"hooks made changes\" — even
  though all hooks individually report \"Passed\".

## Fix

Two complementary parts:

**1. Release-time (structural):**

\`\`\`toml [tool.semantic_release] build_command = "uv lock && git add uv.lock" \`\`\`

\`semantic-release\` runs the \`build_command\` after the version bump, before the release commit.
  The explicit \`git add\` is required because \`semantic-release\` only auto-stages files declared
  in \`version_variables\` / \`version_toml\`. With this in place, every release commit includes
  \`pyproject.toml\` + \`__init__.py\` + \`uv.lock\` aligned.

The release workflow drops \`build: false\` from the action so the build_command actually runs.

**2. PR-time (defense in depth):**

New \`uv-lock-locked\` pre-commit hook runs \`uv lock --locked\`, which exits non-zero if the
  lockfile is out of sync with \`pyproject.toml\`. Catches drift before push for cases where someone
  forgets to commit a refreshed lock alongside a dependency change.

## Verification

- \`uv run pre-commit run --all-files\` — green; new \`uv-lock-locked\` hook is listed and passes
  against the current synced lock. - \`uv lock --locked\` exits 0 against the current state. - The
  release-time fix can only be verified end-to-end at the next release. If \`uv.lock\` lands stale
  despite this change, the pre-commit guard catches it on the very next PR — so no risk of silent
  regression.

## Files

- \`pyproject.toml\` — \`build_command\` for semantic-release. - \`.github/workflows/release.yml\` —
  drop \`build: false\` so build_command runs. - \`.pre-commit-config.yaml\` — new
  \`uv-lock-locked\` hook.

Closes #44.

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

- **scripts**: Auto-install pre-commit git hook in session_start
  ([#47](https://github.com/cdds-ab/vaultctl/pull/47),
  [`8412de4`](https://github.com/cdds-ab/vaultctl/commit/8412de47e7a94f508609692d1f1805057227866e))

## Summary

Fixes the parity gap that caused PR #41 to fail CI on a SIM108 lint issue I missed locally — by
  ensuring the git pre-commit hook is installed, so \`git commit\` blocks on hook failures instead
  of relying on memory.

## Root Cause

\`pre-commit\` is configured in \`.pre-commit-config.yaml\` and runs cleanly via \`uv run pre-commit
  run --all-files\`, but it does **not** auto-install the git hook into \`.git/hooks/pre-commit\`.
  Without that hook, \`git commit\` runs straight through without any verification. The CLAUDE.md
  note (\"Pre-commit hooks will run automatically on commit\") was true *only if* a contributor had
  previously run \`pre-commit install\` — easy to miss, especially in a fresh clone or after
  \`.git/hooks\` cleanup.

In #41 I ran \`pre-commit run --all-files\` manually, missed a Failed line buried in the long output
  (ruff SIM108), committed and pushed, then watched CI catch it. The mistake was discipline; the
  structural fix is to make \`git commit\` itself the gate.

## Fix

\`scripts/session_start.py\` now checks \`.git/hooks/pre-commit\` and, if the hook is missing or
  doesn't reference pre-commit, runs \`uv run pre-commit install\`. The check is idempotent —
  already-installed hooks are reported and untouched.

The script is documented as the standard session start entry point in CLAUDE.md, so the auto-install
  runs as part of normal workflow.

CLAUDE.md's Session Start subsection is updated to mention the new behavior and link to #45 for the
  incident context, so future-me / future contributors understand why this exists.

## Verification

\`\`\`bash $ rm .git/hooks/pre-commit $ uv run python scripts/session_start.py ... Pre-commit git
  hook installed (was missing — \`git commit\` now blocks on hook failures). ...

$ uv run python scripts/session_start.py ... Pre-commit git hook is installed. ... \`\`\`

Idempotent across runs; no state corruption if invoked from a session that already has the hook.

The commit creating this PR was itself made through the now-installed hook — verifiable by the
  inline \`pre-commit\` output in the commit log.

## What's NOT in This PR

The original issue body floated \`--exit-non-zero-on-fix\` on the ruff hook as a candidate fix.
  After analysis it doesn't help with the SIM108 case: that flag triggers only when ruff applied a
  fix, but SIM108's fix

is unsafe and wasn't applied, so default ruff behavior already exits non-zero. The structural fix
  (git hook installation) addresses the actual gap.

Closes #45.

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v1.2.0 (2026-04-27)

### Documentation

- **landscape**: Introduce vaultctl landscape with first ADR
  ([#43](https://github.com/cdds-ab/vaultctl/pull/43),
  [`f0728c0`](https://github.com/cdds-ab/vaultctl/commit/f0728c01a6c85b6f284f824f7682edb60f4b312e))

## Summary

Adds \`docs/landscapes/vaultctl/\` with a LANDSCAPE.md entry point and the first Architecture
  Decision Record (ADR): the rationale for using a pure-Python walker for schema inference rather
  than shelling out to \`cue import\`.

## Why a Landscape Here

Per global Claude Code guideline, tool repos typically don't have a landscape — landscapes group
  cross-repo work for client engagements (Zeiss, Aldi, ...). vaultctl is treated as a deliberate
  exception:

- Tool is at v1.x. - Has accumulated several cross-cutting design choices that are scattered across
  PR descriptions and CLAUDE.md sections. - A central, ADR-style location makes them discoverable
  for future contributors and the user's future self.

The LANDSCAPE.md flags this convention deviation explicitly and notes the directory can collapse to
  a flat \`docs/decisions/\` later without losing the ADR files.

## What's in the First ADR

\`0001-schema-inference-via-python-walker.md\` captures the design relationship behind the
  implementation choice in PR #41:

- **Why not \`cue import\`**: it produces concrete data in CUE syntax, not a schema. We'd still need
  a value-to-type substitution pass — which is the bulk of the work — so wrapping it around a
  subprocess hop adds complexity without removing any. - **Why pure Python**: self-contained, no
  extra subprocess, testable without external binaries, deterministic output suitable for
  git-tracking. - **Trade-off**: we don't get CUE's parser for free. Edge cases surface as Python
  errors. Acceptable because vault content comes from \`pyyaml\` upstream, which already raises
  before the walker runs. - **Alternatives explicitly rejected**: \`cue import\` + AST
  post-processing, native Python CUE binding (none production-ready), JSON Schema indirection.

## Backfill Backlog (Not in This PR)

LANDSCAPE.md lists existing-but-undocumented decisions worth ADR'ing later:

- Python over Go/Rust (originated in our session discussion before #36). - CUE validation via
  \`cue\` binary subprocess (rationale in #34/PR #39). - Project-local \`.vaultctl/\` layout, no
  backward compat (#37/PR #38).

These remain in their PR bodies and CLAUDE.md sections for now — promoting them to ADRs is a P4
  chore I can pick up incrementally.

## Files

- \`docs/landscapes/vaultctl/LANDSCAPE.md\` (new) -
  \`docs/landscapes/vaultctl/decisions/0001-schema-inference-via-python-walker.md\` (new) -
  \`CLAUDE.md\` (Landschaften-line referencing the new landscape, per global pattern)

Closes #42. Refs #40, #41.

## Test Plan

- [x] Markdown renders cleanly (verified locally). - [x] Cross-references work (\`#41\`, \`#34\`,
  \`#40\`). - [ ] CI green.

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

### Features

- **schema**: Vaultctl schema infer for baseline generation (#40 phase 1)
  ([#41](https://github.com/cdds-ab/vaultctl/pull/41),
  [`737f58a`](https://github.com/cdds-ab/vaultctl/commit/737f58a5cb6b151b92ea7b5f9e0d18be1a4794cd))

## Summary

First phase of the schema lifecycle (#40): derive a closed CUE schema baseline from the current
  vault content. Users now have a clear starting point that covers exactly the keys and shapes in
  their vault — without writing CUE by hand.

## New Command

\`\`\`bash vaultctl schema infer # writes .vaultctl/vault.cue (5 keys) vaultctl schema infer --force
  # overwrite an existing baseline vaultctl schema infer --output some.cue \`\`\`

The generated file:

\`\`\`cue // AUTO-GENERATED by \`vaultctl schema infer\` — do not hand-edit. // Project-specific
  constraints (regex, ranges, required fields) belong in // vault.constraints.cue alongside this
  file. CUE merges both at validation time.

package vaultctl

#VaultFile: { 	api_token: string 	db_creds: { 		password: string 		type: string 		username: string
  	} 	hosts: [...string] 	port: int 	enabled: bool } \`\`\`

The schema is **closed** — adding a new vault key without re-running \`infer\` (or extending the
  schema by hand) makes \`vaultctl validate\` fail. That is the value: structural changes become
  deliberate, reviewable steps.

## Why Pure-Python, Not \`cue import\`

\`cue import data.yml\` produces concrete CUE values (\`username: \"admin\"\`), not type constraints
  (\`username: string\`). To get a schema, we'd still have to walk the imported AST and substitute
  types for values — that's the bulk of the work, and doing it in Python keeps the implementation
  self-contained without a second cue invocation per key.

The walker maps Python types directly: \`bool\` → \`bool\` (checked before \`int\` because of
  Python's class hierarchy), \`str\` → \`string\`, nested \`dict\` → nested struct, homogeneous
  \`list[T]\` → \`[...T]\`, mixed list → \`[...(int | string)]\` style disjunction. \`_previous\`
  backup keys are excluded; field names with non-identifier characters get quoted.

## Baseline + Constraints Pattern

The auto-generated file is **machine-managed** — re-running \`infer\` overwrites it. Hand-edited
  rules belong next to it:

\`\`\` .vaultctl/ ├── vault.cue # auto-generated, can be overwritten by infer └──
  vault.constraints.cue # hand-edited, never touched by tooling \`\`\`

CUE's package merging unifies both at validation time. To make this work, \`_run_cue_vet\` now
  optionally passes sibling \`.cue\` files alongside the override schema. Bundled schemas are still
  loaded standalone (no spurious merging from unrelated bundled files).

A round-trip test (\`test_infer_merges_with_user_constraints_file\`) exercises the full path: infer
  → add constraint regex → validate fails on the constraint.

## Files

- \`src/vaultctl/schema.py\` — \`infer_vault_schema()\`, \`_render_type()\`, \`_quote_field()\`,
  \`_siblings_of()\`. \`_run_cue_vet\` and \`validate_yaml_against_schema\` now take
  \`include_siblings\`. - \`src/vaultctl/cli.py\` — new \`@main.group(\"schema\")\` with \`infer\`
  subcommand. Click subcommand groups are how we'll add \`sync\` and (later) \`extend\` without
  polluting the top-level command surface. - \`tests/test_schema.py\` — 11 inference tests (pure
  Python) + 3 cue-required round-trip tests including the constraints-merge case. -
  \`tests/test_cli.py\` — 3 CLI tests covering default path, \`--output\`, \`--force\` overwrite
  protection. - \`README.md\` — Schema Validation section now covers \`infer\` and the baseline +
  constraints pattern. - \`CLAUDE.md\` — Architecture decision 7 documents the inference design (why
  no \`cue import\`).

## What's NOT in This PR

The remaining phases of #40:

- **\`vaultctl schema sync\`** — non-interactive drift detection (compare current schema to what
  \`infer\` would produce, optional \`--apply\`). Builds on this PR's inference function. Smaller
  scope, separate PR. - **Schema-aware \`set\`** — interactive prompt when \`set\` introduces a
  structure not covered by the schema. UX work, separate PR.

This staging keeps each PR reviewable and lets validation be useful even without sync/extend.

## Test Plan

- [x] \`uv run pytest\` — 360 passed (was 344), 88% coverage. - [x] \`uv run mypy src/vaultctl\`
  strict — clean. - [x] \`uv run pre-commit run --all-files\` — green. - [x] Manual: \`vaultctl
  schema infer\` against a fresh vault, then \`vaultctl validate\` round-trip — both green; adding
  an unexpected key reproducibly fails validate. - [ ] CI green.

Refs #40.

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v1.1.0 (2026-04-27)

### Features

- **schema**: Cue-based validation and vaultctl validate command
  ([#39](https://github.com/cdds-ab/vaultctl/pull/39),
  [`1970207`](https://github.com/cdds-ab/vaultctl/commit/19702079ded369590406888c4bf78ced0bbec5a1))

## Summary

Adds CUE-based schema validation as a new feature class. \`vaultctl validate\` checks the project
  against bundled CUE schemas (typo detection, type and date constraints), runs cross-file
  consistency checks, and exits non-zero on any violation — usable as a CI gate or pre-commit hook.

The \`cue\` binary is shelled out to via subprocess, mirroring the existing pattern for
  \`ansible-vault\`. No native Python CUE binding is production-ready as of April 2026 (see issue
  body for the survey), so subprocess remains the realistic state of the art.

## What's New

**\`vaultctl validate\` command** — runs four classes of check:

1. **Config schema** — \`.vaultctl/config.yml\` against bundled \`#Config\` (catches \`pasword:\`
  style typos and wrong types). 2. **Metadata schema** — \`vault-keys.yml\` against bundled
  \`#KeysFile\` (rejects unknown fields, invalid \`type:\` values, malformed \`expires:\` dates;
  accepts both \`YYYY-MM-DD\` and full RFC 3339). 3. **Content schema** — \`vault.yml\` decrypted
  content against bundled \`#VaultFile\` (permissive default; opt out with \`--skip-content\`). 4.
  **Cross-consistency** — every key in \`vault.yml\` has matching metadata in \`vault-keys.yml\` and
  vice versa. Pure Python, runs even when \`cue\` is missing. \`_previous\` backup keys are exempt.

**User schema overrides:**

\`\`\` .vaultctl/ ├── config.yml ├── vault.cue # replaces bundled #VaultFile (e.g. enforce min
  password length) └── keys.cue # replaces bundled #KeysFile (e.g. require descriptions) \`\`\`

**Graceful fallback:** If \`cue\` is not on \`\$PATH\`, schema checks are skipped with a warning and
  a link to install instructions; the cross-consistency check still runs and exit code reflects its
  outcome.

**PyInstaller binary** now bundles \`schemas/*.cue\` via \`--add-data\` so the standalone binary can
  validate too.

## Why This Approach

**Subprocess to \`cue\`, not a Python binding:** - \`pycue\` (PyPI, tebeka) — alpha, last release
  April 2024, marked inactive. - \`cue-py\` (official, cue-lang/cue#3100) — opened April 2024, still
  no production release. - \`philipdexter/pycue\` — minimal, abandoned. - All three would wrap
  \`libcue\` (Go) via CFFI anyway. Direct subprocess is honest about the dependency and avoids CFFI
  complexity.

**Closed schema definitions** (\`#Config\`, \`#KeysFile\`) — they reject unknown top-level fields,
  which is the whole point: catching typos that \`load_config\` would silently ignore.

**Cross-consistency in Python, not CUE** — CUE *can* express this constraint, but expressing "for
  every key in dataset A there's a matching key in dataset B" via two separate file inputs is
  awkward in cue. Python is clearer here, and works without the binary.

**Bundled defaults, user overrides** — projects that don't need strict rules get value out of the
  box. Projects with stricter requirements (regex constraints on passwords, required \`description\`
  fields, etc.) drop their own \`.cue\` next to the config.

## Files

- \`src/vaultctl/schema.py\` — new module: subprocess wrapper, validation orchestration,
  importlib.resources for bundled schema discovery. -
  \`src/vaultctl/schemas/{config,keys,vault}.cue\` — bundled CUE schemas. -
  \`src/vaultctl/schemas/__init__.py\` — empty marker so the schemas dir is a package (resources
  discoverable). - \`src/vaultctl/cli.py\` — \`vaultctl validate\` command. -
  \`tests/test_schema.py\` — 19 tests with \`requires_cue\` skip marker. - \`tests/test_cli.py\` — 4
  CLI-level validate tests covering cross-check, skip-content, missing-cue, and aligned-vault paths.
  - \`.github/workflows/release.yml\` — PyInstaller \`--add-data\` flag. - \`README.md\`,
  \`CLAUDE.md\` — Schema Validation section, command table, architecture notes.

## What's NOT in this PR

The earlier discussion floated a \"schema lifecycle\" — \`vaultctl schema infer\` (generate from
  existing vault), \`vaultctl schema sync\` (auto-extend on new structure), interactive
  schema-update on \`set\`. That's a separate, larger feature class and gets its own issue once the
  validation foundation is in.

\`vaultctl import <yaml>\` (Use Case 3 from #34) is also deferred — it builds on the validation
  foundation but introduces its own design questions (merge semantics, conflict handling) better
  tackled separately.

Closes #34.

## Test Plan

- [x] \`uv run pytest\` — 344 passed (was 321 before this PR), 88% coverage. - [x] \`uv run mypy
  src/vaultctl\` strict — clean. - [x] \`uv run bandit -r src/vaultctl\` — no new findings. - [x]
  \`uv run pre-commit run --all-files\` — green. - [x] Manual: \`cue vet\` invocations against good
  and bad fixtures verified locally before integration. - [ ] CI green. - [ ] PyInstaller artifacts
  contain the schemas (will verify on next release tag).

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v1.0.0 (2026-04-27)

### Documentation

- **readme**: Document required external binaries
  ([#36](https://github.com/cdds-ab/vaultctl/pull/36),
  [`590f6a5`](https://github.com/cdds-ab/vaultctl/commit/590f6a510274bec8ef7c2b22cb4bd1811c08d99d))

## Summary

Adds a "Required external tools" subsection to the README's Install section, listing the external
  binaries vaultctl shells out to.

**What changes:** - Documents `ansible-vault` as a hard dependency (previously implicit — users had
  to discover this from error messages or the source). - Pre-announces `cue` as an optional
  dependency for the upcoming schema-validation feature (#34), with a clear note that vaultctl will
  gracefully skip schema features when `cue` is missing.

**Why now:** The `ansible-vault` documentation gap has existed since the project was extracted from
  the customer-specific tooling. We close it on the occasion of #34, which adds a second external
  binary (`cue`) and forced us to articulate the dependency model. Documenting both at once keeps
  the README consistent and avoids a second touch later.

**Why this approach:** External binaries (subprocess) instead of native Python bindings, mirroring
  the existing `ansible-vault` pattern. Rationale for `cue` specifically: no production-ready native
  Python binding for CUE exists

as of April 2026 (`pycue` alpha/inactive, official `cue-py` still in development). Subprocess is the
  realistic state of the art and keeps vaultctl free of CFFI/CGO complexity.

Closes #35. Refs #34.

## Test plan

- [x] README diff visually reviewed — section renders correctly under "## Install" - [x]
  Cross-references (#34) link to the right issue - [ ] CI green (lint, test, security, build)

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

### Features

- **config**: Move config into .vaultctl/ directory
  ([#38](https://github.com/cdds-ab/vaultctl/pull/38),
  [`b6e2685`](https://github.com/cdds-ab/vaultctl/commit/b6e26858d58454ba3b47df424c0bf3bf811ba4c6))

## Summary

Replaces the root-level \`.vaultctl.yml\` with a project-local \`.vaultctl/\` directory. The
  directory is the future home for all vaultctl-managed metadata — config today, CUE schemas (#34)
  next.

**Before:** \`\`\` project-root/ ├── .vaultctl.yml # config at root ├── inventory/group_vars/all/ │
  ├── vault.yml │ └── vault-keys.yml \`\`\`

**After:** \`\`\` project-root/ ├── .vaultctl/ │ └── config.yml # config in dedicated dir ├──
  inventory/group_vars/all/ │ ├── vault.yml # unchanged │ └── vault-keys.yml # unchanged \`\`\`

## What Changed

**Discovery (\`config.py\`):** - \`find_config()\` now searches for \`.vaultctl/config.yml\` upwards
  from CWD to git root. - New helper \`_resolve_config_dir()\` decides where vault/keys paths
  anchor: for the convention layout (\`.vaultctl/config.yml\`) it's the

project root (parent of \`.vaultctl/\`); for an arbitrary \`--config <path>\` override it falls back
  to the file's own directory. - This is the key design point: vault and keys files keep their
  natural Ansible location, the directory only holds vaultctl-specific metadata.

**Init (\`cli.py\`):** - \`vaultctl init\` creates \`.vaultctl/\` and writes \`config.yml\` inside.
  - Error messages and help text reference the new path.

**Documentation:** - README's "Configuration" and "Troubleshooting" sections updated. - CLAUDE.md's
  "Configuration discovery" design decision rewritten to explain the project-root anchoring rule.

**Tests:** - \`test_config.py\` now writes configs under the convention layout via a small helper.
  Added two new cases: walking-up-from-deep-subdirectory discovery, and the arbitrary-path
  \`--config\` override behavior. - \`conftest.py\` \`config_file\` fixture uses the new layout.

## Why Now

Prerequisite for #34 (CUE-based schema validation). The CUE schema files (\`vault.cue\`,
  \`vault.constraints.cue\`) need a home, and shipping them next to a root \`.vaultctl.yml\` only to
  move everything later would be churn. Doing the directory restructure first means #34 lands at the
  final paths from day one.

The \`ansible-vault\` documentation gap (just closed in #36) and the CUE work also forced a clearer
  articulation of vaultctl's "what's tool-config vs. what's data" model — this PR encodes that model
  in the file layout.

## Why No Backward Compatibility

vaultctl has no production users yet (confirmed at session start). A deprecation phase, parallel
  discovery, or migration command would all be unnecessary code paths. Cleanest possible cut keeps
  the architecture lean and the design intent visible.

Closes #37. Refs #34.

## Test Plan

- [x] \`uv run ruff check\` clean - [x] \`uv run mypy src/vaultctl\` strict — no issues - [x] \`uv
  run bandit -r src/vaultctl\` — no new findings (10 pre-existing low/high-confidence items
  unchanged) - [x] \`uv run pytest\` — 321 passed, 87.55% coverage (well above 70% threshold) - [x]
  \`uv run pre-commit run\` on all changed files — green - [ ] CI green

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.12.0 (2026-03-14)

### Features

- **cli**: Add --raw and --base64 flags for clean SSH key import/export
  ([#33](https://github.com/cdds-ab/vaultctl/pull/33),
  [`10a7ed8`](https://github.com/cdds-ab/vaultctl/commit/10a7ed8c6b369a6b0afd7b10445e503db422a185))

## Summary

SSH private keys and certificates stored in Ansible Vault suffer from whitespace corruption during
  YAML multiline formatting. This PR adds clean import/export modes to prevent these issues.

- **`get --raw`**: Outputs value without Type: headers or field labels, strips trailing whitespace
  per line, ensures single trailing newline. Ideal for `vaultctl get key --field privateKey --raw >
  key.pem` - **`get --base64`**: Outputs value as a single base64-encoded line, suitable for
  environments that cannot handle multiline values - **`set --base64`**: Accepts an inline
  base64-encoded value, decodes before storing - **`set --base64-file`**: Reads base64 from a file
  or stdin (`-`), decodes before storing - **`set --file`**: Now applies whitespace cleanup
  (trailing space removal) on import - **`clean_multiline_value()`**: New helper that strips
  trailing whitespace per line and ensures exactly one trailing newline

## Problem

When SSH keys are stored in YAML via `ansible-vault`, the multiline formatting introduces trailing
  spaces on lines. Extracting these keys with `vaultctl get ... --json | jq -r` produces keys that
  SSH rejects. There was no way to get a clean, whitespace-safe export or to import base64-encoded
  values.

## Changed Files

| File | Change | |------|--------| | `src/vaultctl/cli.py` | Added `--raw` and `--base64` flags to
  `get`, `--base64` and `--base64-file` options to `set`, mutual exclusivity validation,
  `_output_raw()` and `_output_base64_encoded()` helpers | | `src/vaultctl/yaml_util.py` | Added
  `clean_multiline_value()` helper | | `tests/test_cli.py` | 17 new integration tests covering all
  new flags and edge cases | | `tests/test_yaml_util.py` | 7 unit tests for
  `clean_multiline_value()` | | `tests/conftest.py` | Added `ssh_key` fixture entry with trailing
  whitespace for testing |

## Design Decisions

1. **`clean_multiline_value` in `yaml_util.py`** — It is a value formatting utility closely related
  to YAML handling, keeping it here avoids a new module for one function 2. **Mutual exclusivity of
  `--json`, `--raw`, `--base64`** — Validated at runtime with a clear error message rather than
  Click's `cls=MutuallyExclusiveOption` to keep it simple 3. **`--file` now cleans whitespace on
  import** — Prevents storing corrupted values at the source. This is a minor behavioral change but
  strictly an improvement 4. **`--base64-file -` for stdin** — Follows Unix convention, enables
  piping: `cat key.pem | base64 | vaultctl set key --base64-file -`

## Test Plan

- [x] `get --raw` on plain strings outputs clean value - [x] `get --raw` on multiline values strips
  trailing whitespace - [x] `get --raw --field` extracts single field without headers - [x] `get
  --raw` on structured entries outputs YAML without Type: header - [x] `get --base64` produces valid
  single-line base64 - [x] `get --base64` on multiline values cleans before encoding - [x] `get
  --base64 --field` works on individual fields - [x] `--json`, `--raw`, `--base64` are mutually
  exclusive - [x] `set --base64` decodes and stores correctly - [x] `set --base64` rejects invalid
  input - [x] `set --base64-file` reads from file - [x] `set --base64-file -` reads from stdin - [x]
  `set --file` cleans trailing whitespace - [x] Multiple input sources rejected - [x]
  `clean_multiline_value` unit tests (7 cases) - [x] All 319 tests pass, coverage 88%

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.11.1 (2026-03-14)

### Bug Fixes

- **cli**: Format nested values as YAML and add --json flag to get
  ([#32](https://github.com/cdds-ab/vaultctl/pull/32),
  [`899ab2d`](https://github.com/cdds-ab/vaultctl/commit/899ab2df0ac1566497c51abc9c24b115989e632c))

## Problem

`vaultctl get` on structured entries (dicts, lists) outputs Python `repr()` format — single quotes,
  no indentation, not parseable by `jq` or other tools. Example:

``` Type: secretText

domains: [{'name': 'docker build hosts', 'credentials': [{'type': 'x509ClientCert', ...

```

This makes credentialStore entries with 50+ nested credentials completely unreadable.

## Solution

### 1. Human-readable output: YAML formatting

Added `_format_value()` helper (`cli.py:35-46`) that formats nested values: - **Strings**: returned
  as-is (no change to existing behavior) - **Dicts/Lists**: formatted as YAML via
  `yaml.dump(default_flow_style=False)` - **Other types**: converted via `str()`

The `get` command now calls `_format_value(value[f])` instead of directly printing `value[f]`, so
  nested structures render as readable YAML with proper indentation.

### 2. Machine-readable output: `--json` flag

New `--json` flag on the `get` command outputs the value as JSON:

```bash vaultctl get vault_jenkins_credentials --json | jq '.global.credentials | length' ```

Works with `--field` too:

```bash vaultctl get db_creds --field username --json ```

Uses `json.dumps(indent=2, ensure_ascii=False)` for readable JSON that pipes cleanly to `jq`.

### Files changed

- `src/vaultctl/cli.py`: - Added `_format_value()` helper (lines 35-46) - Added `--json` /
  `output_json` option to `get` command - Changed dict field output from `value[f]` to
  `_format_value(value[f])` - JSON output path for both full value and `--field` access

## Test plan - [ ] `vaultctl get <dict-key>` shows readable YAML (not Python repr) - [ ] `vaultctl
  get <dict-key> --json | jq .` parses correctly - [ ] `vaultctl get <string-key>` unchanged (plain
  string output) - [ ] `vaultctl get <dict-key> --field username` unchanged - [ ] All 298 existing
  tests pass

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.11.0 (2026-03-14)

### Features

- **cli**: Add shell completion for bash, zsh, and fish
  ([#31](https://github.com/cdds-ab/vaultctl/pull/31),
  [`7d860d8`](https://github.com/cdds-ab/vaultctl/commit/7d860d879d1af37afdefd14f4e56918ec8a67bee))

## Summary

- New `vaultctl completion <shell>` command (bash, zsh, fish) - Uses Click's `shell_completion` API
  - Works without `.vaultctl.yml` config

## Install

```bash eval "$(vaultctl completion bash)" # bash eval "$(vaultctl completion zsh)" # zsh vaultctl
  completion fish > ~/.config/fish/completions/vaultctl.fish # fish ```

## Test plan - [ ] `vaultctl completion bash` outputs valid bash completion - [ ] `vaultctl
  completion zsh` outputs valid zsh completion - [ ] `vaultctl completion fish` outputs valid fish
  completion - [ ] Tab completion works after eval

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.10.0 (2026-03-14)

### Features

- **search**: Add --context flag to show parent object of matches
  ([#30](https://github.com/cdds-ab/vaultctl/pull/30),
  [`47a015e`](https://github.com/cdds-ab/vaultctl/commit/47a015ee7924c640581cad6356ccb417d1f9fc58))

## Summary

- Add `--context / -c` flag to `vaultctl search` that shows the parent dict of each matched field -
  Sibling fields are redacted by default (`****`), matched field shows first 4 chars + `...` -
  Combine with `--show-match` to display all field values in cleartext - Multiple matches in the
  same parent object are grouped into a single block

Closes #20

## Test plan

- [x] Unit tests for `search_values(include_context=True)` covering nested dicts, lists, top-level
  strings, multiple matches - [x] CLI integration tests for `--context`, `--context --show-match`,
  and top-level string fallback - [x] All 298 tests pass, 88% coverage - [x] mypy strict, ruff,
  bandit clean

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.9.0 (2026-03-14)

### Features

- **cli**: Add search command and list --filter ([#29](https://github.com/cdds-ab/vaultctl/pull/29),
  [`007f505`](https://github.com/cdds-ab/vaultctl/commit/007f50557b165d55d0e21ca59f5d0ee8b6777065))

## Summary

- **`vaultctl list --filter/-f PATTERN`**: Regex filter on key names, descriptions, and consumers
  from vault-keys.yml metadata. No additional decryption beyond what `list` already does. -
  **`vaultctl search PATTERN`**: New subcommand that decrypts the vault and recursively searches all
  values (strings in nested dicts/lists). Output shows only key names and dot-path locations — never
  values unless `--show-match` is explicitly used. - `--keys-only / -k`: Search only key names and
  metadata (no vault decryption needed) - `--show-match`: Display matched values (with security
  warning) - Exit code 0 if matches found, 1 if not (scripting-friendly)

### Security considerations - Search pattern is never logged or included in error output - Values
  are never shown without explicit `--show-match` flag - `--show-match` displays a yellow WARNING to
  stderr - Recursive search is depth-limited (max 20 levels) - All search logic is in a
  pure-function module (`search.py`) — no side effects

### Architecture - New module `src/vaultctl/search.py` with `search_values()` and `filter_keys()` —
  pure functions, fully unit-testable - CLI wiring in `cli.py` follows existing command patterns -
  100% test coverage on search.py, 87% overall

Closes #TBD

## Test plan

- [x] Unit tests for `search_values()` — flat values, nested dicts, nested lists, depth limit,
  include_values toggle - [x] Unit tests for `filter_keys()` — key name, description, consumer
  matching, regex, case insensitivity - [x] Integration tests for `vaultctl list --filter` — name
  match, description match, regex, no match, invalid regex - [x] Integration tests for `vaultctl
  search` — value found, not found, nested, show-match, keys-only, invalid regex - [x] All 272 tests
  pass, 87.45% coverage - [x] ruff, mypy --strict, bandit all clean

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.8.2 (2026-03-14)

### Bug Fixes

- **detect**: Support lists as top-level vault values in recursive detection
  ([#28](https://github.com/cdds-ab/vaultctl/pull/28),
  [`9bc77b4`](https://github.com/cdds-ab/vaultctl/commit/9bc77b435d6d6e16b223c88079bf68bb98689fd7))

## Summary

- `_collect_nested_credential_types()` now handles list values directly (not only lists inside
  dicts) - `detect_type_heuristic()` checks `isinstance(value, (dict, list))` for credential store
  detection - Fixes detection for vault entries that are credential lists at the top level - 5 new
  tests for list-based credential structures

## Test plan - [ ] `uv run pytest` — 237 tests green - [ ] `vaultctl detect-types` on vaults with
  list-based credential entries

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

### Documentation

- Add troubleshooting section to README ([#27](https://github.com/cdds-ab/vaultctl/pull/27),
  [`1384c43`](https://github.com/cdds-ab/vaultctl/commit/1384c43c23680e5b1baf725de7e70e9e64956904))

## Summary

Adds troubleshooting section covering the most common issues: - Decryption failures from
  missing/misconfigured password source - Config file not found - `init` overwriting password config
  on re-run - `self-update` on pip/uv installs

## Test plan - [ ] README renders correctly on GitHub

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.8.1 (2026-03-14)

### Bug Fixes

- **security**: Add recursion limits, redaction runtime guard, and security docs
  ([#26](https://github.com/cdds-ab/vaultctl/pull/26),
  [`9bcf6e2`](https://github.com/cdds-ab/vaultctl/commit/9bcf6e2f6bdb3cf270a8a47d3986be0cf9908abc))

## Summary

- **F-04**: Recursion depth limit (max 50) in `_collect_nested_credential_types()` and
  `redact_value()` - **A-01**: Runtime redaction guard in `build_payload()` using
  `contains_unredacted()` — aborts AI detection if redaction fails - **F-05**: Trust-boundary
  comments on `shell=True` in `password.py` and `ai_detect.py` - **docs/SECURITY.md**: Comprehensive
  security architecture documentation covering data flow, triple-layer AI protection, trust
  boundaries, and verification steps - 7 new tests for recursion limits and redaction guard

Based on findings from cybersecurity audit of #24.

## Test plan - [ ] `uv run pytest` — all 233+ tests green - [ ] Review `docs/SECURITY.md` for
  completeness - [ ] `vaultctl detect-types --show-payload` still works correctly

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.8.0 (2026-03-14)

### Features

- **detect**: Recursive type detection for nested credential structures
  ([#25](https://github.com/cdds-ab/vaultctl/pull/25),
  [`aafbfed`](https://github.com/cdds-ab/vaultctl/commit/aafbfedc365744727631018e2654e649f679af5f))

## Summary - Adds recursive scanning of nested dict/list structures for credential type fields -
  Detects Jenkins JCasC-style credential stores - New credentialStore type with sub-type summary -
  10 new tests

Closes #24

## Test plan - [ ] uv run pytest — all tests green - [ ] vaultctl detect-types on real Jenkins JCasC
  vault shows nested types - [ ] Existing detection behavior unchanged

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.7.2 (2026-03-13)

### Bug Fixes

- **self-update**: Improve module docstring for clarity
  ([`7832596`](https://github.com/cdds-ab/vaultctl/commit/7832596de1a4139d60021b28d450f6b7902ca226))


## v0.7.1 (2026-03-13)

### Bug Fixes

- **ci**: Drop macos-amd64 binary build (unreliable macos-13 runner)
  ([`59bf347`](https://github.com/cdds-ab/vaultctl/commit/59bf347d9897868c3194bad6ba3ea384bd077919))


## v0.7.0 (2026-03-13)

### Features

- **cli**: Standalone binary with self-update and checksum verification
  ([#23](https://github.com/cdds-ab/vaultctl/pull/23),
  [`e49710c`](https://github.com/cdds-ab/vaultctl/commit/e49710cd2d270530694ad1dab79b8f6a0d3b8fd1))

## Summary

- Add `vaultctl self-update` command that downloads the latest release from GitHub - SHA256 checksum
  verification before replacing the binary (checksums.sha256 asset) - Release workflow builds
  standalone PyInstaller binaries for linux-amd64, macos-amd64, macos-arm64 - Graceful fallback when
  no checksums available (older releases) - Temp file cleanup on checksum mismatch or download
  failure

Closes #23

## Test plan

- [x] 16 unit tests for self-update module (platform detection, checksum verification, update flow)
  - [x] Full test suite passes (190 tests, 85% coverage) - [x] Bandit security scan clean - [ ]
  Verify PyInstaller binary build in CI - [ ] Verify checksums.sha256 uploaded to release

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.6.0 (2026-03-13)

### Features

- **ai**: Add AI-assisted type detection with GDPR consent
  ([#22](https://github.com/cdds-ab/vaultctl/pull/22),
  [`da4a4af`](https://github.com/cdds-ab/vaultctl/commit/da4a4af685a9f791e682ee024b1b6a53d37c37ee))

## Summary Phase 2 of #19: AI-assisted vault entry type detection with security and GDPR compliance.

- **`ai_detect.py`**: AI client module with: - Mandatory redaction (all data passes through
  `redact_vault_data()`) - Exception firewall (no secrets in error messages) - TLS enforcement
  (HTTPS required for remote, HTTP only for localhost/Ollama) - Untrusted response parsing (JSON
  string literals only, no eval) - Phase 1 / AI result merging (local heuristics take priority) -
  **`config.py`**: `AIConfig` dataclass with endpoint, model, api_key_cmd, consent state - **CLI
  flags**: `--ai`, `--show-payload`, `--yes` (skip consent for CI) - **GDPR consent flow**:
  Interactive disclosure of what data is sent, to where, with opt-in - **Graceful fallback**: AI
  failure falls back to Phase 1 local heuristics

### Security measures (from security review): - API key resolved via command (never stored in
  config, never logged) - No vault secrets in any error message or exception - Payload hash for
  audit trail - Data minimization: only key names, field names, Phase 1 hints sent

Closes #19

## Test plan - [x] 23 unit tests for ai_detect.py (payload building, endpoint validation, API key,
  response parsing, result merging) - [x] 3 CLI integration tests (show-payload, ai-no-config
  fallback, consent prompt) - [x] No secrets in `--show-payload` output verified - [x] All 174 tests
  pass - [x] mypy strict + ruff clean

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.5.0 (2026-03-12)

### Features

- **cli**: Add detect-types command ([#21](https://github.com/cdds-ab/vaultctl/pull/21),
  [`a873a28`](https://github.com/cdds-ab/vaultctl/commit/a873a283a07679e11615768977bb8996169f9f8e))

## Summary - New CLI command `vaultctl detect-types` with heuristic type detection - `--apply`
  writes detected types to vault entries and keys metadata - `--show-redacted` displays safe
  redacted vault structure for auditing - `--json` and `--confidence` for machine-readable and
  filtered output - Test fixture extended with `untyped_creds` entry for detection testing

Part 2 of #19

## Test plan - [x] 5 new integration tests (dry-run, JSON, confidence filter, show-redacted, apply)
  - [x] `--show-redacted` verified: no secrets in output - [x] `--apply` verified: detected type
  persisted and visible in `get` - [x] All 148 tests pass - [x] mypy strict + ruff clean

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.4.0 (2026-03-12)

### Features

- **detect**: Add heuristic type detection and vault data redaction
  ([#20](https://github.com/cdds-ab/vaultctl/pull/20),
  [`a160ed9`](https://github.com/cdds-ab/vaultctl/commit/a160ed958ff957bc87bd6f64cd101bc60cd8a754))

## Summary - **`redact.py`**: Deterministic redaction — replaces all secret values with
  `***REDACTED***`, preserves key names, dict structure, and `type` field values. Includes
  `contains_unredacted()` verification helper for auditing. - **`detect.py`**: Heuristic type
  detection engine with three priority levels: 1. Dict field structure (e.g. `username`+`password` →
  `usernamePassword`) — high confidence 2. Value patterns (PEM headers, ssh-* prefixes) — high
  confidence 3. Key name patterns (e.g. `*_password`, `*_cert`) — medium confidence - Skips
  `_previous` backup keys and entries with explicit `type` field - **74 new tests** covering
  completeness, edge cases, priority ordering

Part 1 of #19 (core modules, no CLI integration yet)

## Test plan - [x] 36 redaction tests (value types, nesting, parametrized completeness) - [x] 38
  detection tests (field patterns, value patterns, key names, priorities) - [x] `mypy --strict`
  clean - [x] `ruff check` clean

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.3.0 (2026-03-12)

### Features

- **cli**: Display structured vault entry types ([#18](https://github.com/cdds-ab/vaultctl/pull/18),
  [`059b9d9`](https://github.com/cdds-ab/vaultctl/commit/059b9d99d34c706acf6ab132d40d768600e111e8))

## Summary - `get`: Shows type + fields for structured entries (dicts), add `--field` flag for
  direct field access - `list`: Shows `[usernamePassword]` type tag for non-secretText entries -
  `describe`: Shows `Type:` line when `entry_type` is set in metadata - Test fixtures extended with
  structured `db_creds` entry - 7 new integration tests

Closes #14

## Test plan - [x] `test_get_structured_entry` — dict entry shows type + fields - [x]
  `test_get_structured_field` — `--field username` returns single value - [x]
  `test_get_structured_field_missing` — missing field exits 1 - [x] `test_get_field_on_plain_string`
  — `--field` on string exits 1 - [x] `test_list_shows_type_tag` — `[usernamePassword]` shown,
  `[secretText]` hidden - [x] `test_describe_structured_entry` — Type line in describe output - [x]
  All 51 tests pass, mypy strict clean, ruff clean

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>


## v0.2.0 (2026-03-11)

### Documentation

- Add PR-based workflow documentation ([#13](https://github.com/cdds-ab/vaultctl/pull/13),
  [`3fdb1b1`](https://github.com/cdds-ab/vaultctl/commit/3fdb1b15e29e871af180826062efaab4d4bdb0c7))

## Summary - Add PR-based workflow documentation to CLAUDE.md - Document branch naming conventions
  (feature/, fix/) - Document PR requirements (Closes #N, CI green, squash merge) - Document branch
  protection rules

## Test plan - [x] CLAUDE.md updated with workflow section - [x] Branch protection configured on
  GitHub - [x] Squash merge as only merge strategy

🤖 Generated with [Claude Code](https://claude.com/claude-code)

---------

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>

### Features

- **keys**: Add entry_type field to KeyInfo dataclass
  ([#16](https://github.com/cdds-ab/vaultctl/pull/16),
  [`53263f0`](https://github.com/cdds-ab/vaultctl/commit/53263f0a35b4b992f02df740fd70bd699fb6e283))

## Summary - Add `entry_type` field to `KeyInfo` dataclass, populated from `type` metadata in
  vault-keys.yml - Enables tracking structured entry types (e.g. `usernamePassword`, `sshKey`) in
  key metadata - Step 2 of #14 (structured vault data types)

## Test plan - [x] 3 new tests: type present, type default (empty), missing key - [x] All 15
  `test_keys.py` tests pass - [x] `mypy --strict` clean - [x] `ruff check` clean

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

- **types**: Add vault entry type detection module
  ([#15](https://github.com/cdds-ab/vaultctl/pull/15),
  [`4203c18`](https://github.com/cdds-ab/vaultctl/commit/4203c185bb4212055fa343da7bdde56b95b07716))

## Summary - Add `src/vaultctl/types.py` with utilities for detecting and accessing structured vault
  entry types (e.g. `usernamePassword`, `sshKey`) - Add `tests/test_types.py` with 13 tests covering
  all type detection and field access functions - Step 1 of #14 (structured vault data types)

Closes #14

## Test plan - [x] `uv run pytest tests/test_types.py` — 13 tests pass - [x] `uv run mypy --strict
  src/vaultctl/types.py` — clean - [x] `uv run ruff check src/vaultctl/types.py` — clean

Co-authored-by: Fred Thiele <8555720+f3rdy@users.noreply.github.com>

Co-authored-by: Claude Opus 4.6 <noreply@anthropic.com>


## v0.1.2 (2026-03-08)

### Documentation

- **password**: Document env var empty-string fallthrough semantics
  ([`6e56fd9`](https://github.com/cdds-ab/vaultctl/commit/6e56fd9473485bcb5ecce01de3cad62dbc55bb22))

Add code comment, README section, and explicit test for the behavior where VAULT_PASS="" is treated
  as unset and falls through to next source.

Closes #12

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

### Refactoring

- **cli**: Switch all user-facing messages from German to English
  ([`912212e`](https://github.com/cdds-ab/vaultctl/commit/912212e28591f59879805926c6228ffaeb36efa8))

Translate ~30 German CLI messages to English and update all test assertions accordingly. No
  functional changes.

Closes #6

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

- **keys**: Introduce Literal type for ExpiryWarning.status
  ([`bb4d9b9`](https://github.com/cdds-ab/vaultctl/commit/bb4d9b95cddef94a74cef1cc23a5fb3a50385f85))

Replace bare `str` with `ExpiryStatus = Literal["expired", "warning", "ok"]` to catch typos at
  type-check time.

Closes #5

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>


## v0.1.1 (2026-03-08)

### Bug Fixes

- **cli**: Improve error message when no config found
  ([`6f62776`](https://github.com/cdds-ab/vaultctl/commit/6f627765de3d01ee874a7b09f61a693c26d460b5))

Closes #1

- **types**: Enforce mypy strict compliance across all modules
  ([`450846b`](https://github.com/cdds-ab/vaultctl/commit/450846b105ccfc7e221762e8bebf01e23bd22680))

Add missing type annotations (dict[str, Any], -> None, etc.) to all public and private functions.
  Remove --ignore-missing-imports from pre-commit mypy args since pyproject.toml overrides handle
  it.

Closes #3 Closes #10

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>

- **vault**: Use secure tempfile permissions (0600) for sensitive data
  ([`efe4ead`](https://github.com/cdds-ab/vaultctl/commit/efe4eade0c7fad77b843d16f8fbd77390a1042d1))

Temporary files containing decrypted vault data and passwords are now created with mkstemp +
  explicit fchmod(0600) via a _secure_tempfile context manager, preventing exposure on shared
  systems.

Closes #9

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>


## v0.1.0 (2026-03-08)

### Features

- Initial vaultctl CLI implementation
  ([`124ba4f`](https://github.com/cdds-ab/vaultctl/commit/124ba4f99df04d0020ade93dfff66a80cd037434))

Generalized Ansible Vault management CLI with: - Commands: init, list, get, set, delete, describe,
  restore, edit, check - YAML config (.vaultctl.yml) with upward search - Password resolution chain
  (env, file, cmd) - Key metadata with expiry tracking (vault-keys.yml) - CI/CD pipeline (GitHub
  Actions), semantic-release, pre-commit hooks - 46 tests, 80% coverage
