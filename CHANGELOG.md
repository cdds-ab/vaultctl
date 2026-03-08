# CHANGELOG


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
