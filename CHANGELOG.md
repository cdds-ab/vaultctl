# CHANGELOG


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
