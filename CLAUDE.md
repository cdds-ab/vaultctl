# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**vaultctl** is a generalized Ansible Vault management CLI. It provides CRUD operations for encrypted secrets with metadata tracking, rotation schedules, and expiry monitoring.

**Key Use Cases:**
- Manage Ansible Vault secrets via a structured CLI
- Track secret metadata (descriptions, rotation schedules, consumers)
- Monitor credential expiry dates
- Standardized workflow for secret rotation with backup

**Abstracted from:** Customer-specific `./vault` CLI (bash) and `credentials-ui` (FastAPI) into a generalized open-source tool.

## Build and Development Commands

```bash
# Install dependencies (first time setup)
uv sync

# Run the CLI during development
uv run vaultctl --help

# Run linting and formatting
uv run ruff check .                # Check for issues
uv run ruff check --fix .          # Auto-fix issues
uv run ruff format .               # Format code

# Type checking
uv run mypy src/vaultctl

# Security scanning
uv run bandit -r src/vaultctl

# Run tests
uv run pytest                      # Run all tests
uv run pytest -v                   # Verbose output
uv run pytest tests/test_vault.py  # Run specific test file
uv run pytest -k "test_config"     # Run tests matching pattern

# Run tests with coverage
uv run pytest --cov=vaultctl --cov-report=term-missing
uv run pytest --cov=vaultctl --cov-report=html

# Install pre-commit hooks (required for contributors)
uv run pre-commit install
uv run pre-commit run --all-files

# Create a conventional commit
uv run cz commit

# Build package
uv build
```

## Architecture Overview

### Modular Structure

```
src/vaultctl/
├── __init__.py        # Version
├── cli.py             # Click CLI with all subcommands
├── config.py          # .vaultctl.yml discovery + loading
├── password.py        # Password fallback chain (env -> file -> cmd)
├── vault.py           # ansible-vault subprocess wrapper
├── keys.py            # vault-keys.yml metadata CRUD + expiry check
└── yaml_util.py       # YAML safe_load/dump helpers
```

### Key Design Decisions

**1. Click CLI (not Typer):**
- Lightweight, no extra dependencies beyond Click itself
- Direct control over group/subcommand structure

**2. ansible-vault as subprocess (not Python library):**
- ansible-vault CLI is stable and universally installed
- The Python API of ansible is unstable and poorly documented
- Subprocess approach is simpler and more robust

**3. Configuration discovery (.vaultctl.yml):**
- Environment variable (`$VAULTCTL_CONFIG`)
- Upward search from CWD to git root
- User-global fallback (`~/.config/vaultctl/config.yml`)
- All paths resolved relative to config file directory

**4. Password resolution chain:**
- Configurable via `.vaultctl.yml` `password:` section
- Environment variable -> File -> Command (subprocess)
- Clear error messages listing tried sources

**5. Metadata separate from secrets:**
- `vault-keys.yml` is NOT encrypted (descriptions, rotation, consumers)
- `vault.yml` is encrypted (actual secret values)
- Expiry tracking via optional `expires` field (ISO 8601)

### CLI Commands

| Command | Description |
|---------|-------------|
| `vaultctl init` | Initialize project (config + empty vault) |
| `vaultctl list` | List all keys with descriptions |
| `vaultctl get <key>` | Show value of a key |
| `vaultctl set <key> <value>` | Set key (inline, --prompt, --file) |
| `vaultctl delete <key>` | Remove key from vault |
| `vaultctl describe <key>` | Show metadata |
| `vaultctl restore <key>` | Rollback to _previous |
| `vaultctl edit` | Open vault in $EDITOR |
| `vaultctl check` | Check expiring/expired keys |

## Technology Stack

- **Package Manager**: `uv`
- **CLI Framework**: `click` (v8.x)
- **YAML**: `pyyaml`
- **Vault Backend**: `ansible-vault` (subprocess)
- **Testing**: `pytest` + `pytest-cov` + `pytest-mock`
- **Linting**: `ruff`
- **Type Checking**: `mypy` (strict)
- **Security**: `bandit`
- **Coverage**: `pytest-cov` (minimum 70%)
- **Commits**: `commitizen` (conventional commits)
- **Releases**: `python-semantic-release` (automated versioning)

## Security & Privacy

### Repository Status
**This repository is PUBLIC.** All issues, commits, and documentation are visible to everyone.

### Automatic Issue Data Sanitization
GitHub Action (`.github/workflows/issue-sanitize.yml`) scans every issue for sensitive patterns (emails, customer names, company URLs) and warns the author.

### Developer Guidelines
- **NEVER commit real credentials** or vault passwords
- **Always use dummy data** in issues and documentation
- **Review PR diffs** for sensitive information before merging

## Development Guidelines

### Code Style
- **All code and documentation in English**
- Use `ruff` for formatting (120 char line length)
- Type hints required for all functions/methods
- Meaningful variable names

### Testing Strategy
- Test behavior, not implementation
- Mock ansible-vault subprocess calls in unit tests
- Use real ansible-vault in integration tests (test fixtures)
- Minimum 70% coverage enforced

### Commit Convention

Uses **Conventional Commits** enforced by Commitizen:

```
<type>(<scope>): <subject>
```

**Rules:**
- **No attribution**: NO "Generated by", "Co-Authored-By", or Claude references
- **Imperative mood**: "Add feature" not "Added feature"
- **Be concise**: Focus on the change, not the process

**Types:**
- `feat`: New feature (MINOR bump)
- `fix`: Bug fix (PATCH bump)
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring (PATCH bump)
- `perf`: Performance improvements (PATCH bump)
- `test`: Adding or updating tests
- `build`: Build system or dependencies
- `ci`: CI/CD pipeline changes
- `chore`: Maintenance

### Pre-commit Hooks

Hooks run on every commit:
1. `ruff` - Format and lint code
2. `mypy` - Type checking (strict)
3. `bandit` - Security scanning
4. `commitizen` - Validate commit message
5. `pytest-cov` - Run tests with minimum 70% coverage

### CI/CD Pipeline Consistency

CI uses `pre-commit/action@v3.0.1` — single source of truth is `.pre-commit-config.yaml`.

## Release Workflow

### Semantic Versioning

Uses `python-semantic-release` for automated releases:

1. Commit with conventional format (enforced by Commitizen)
2. Push to master branch
3. GitHub Actions:
   - Analyzes commits since last release
   - Determines version bump
   - Generates CHANGELOG.md
   - Creates Git tag
   - Publishes to GitHub Releases

**Version Bump Rules:**
- `feat:` -> minor (0.1.0 -> 0.2.0)
- `fix:` -> patch (0.1.0 -> 0.1.1)
- `feat!:` or `BREAKING CHANGE:` -> major (0.1.0 -> 1.0.0)

### GitHub Actions

**Workflows:**
- `.github/workflows/ci.yml` - Push/PR: lint, test, security, build
- `.github/workflows/release.yml` - Push to master: semantic release
- `.github/workflows/issue-sanitize.yml` - Issues: sensitive data detection

**Action versions:**
- `actions/checkout@v5`
- `actions/setup-python@v6`
- `python-semantic-release/python-semantic-release@v9.15.2`

## GitHub Issue Planning

Use GitHub Issues for all feature planning and bug tracking:

### Issue Workflow
1. Create issue with clear description and use cases
2. Label appropriately (bug, enhancement, documentation)
3. Reference issue number in commit messages: `feat(cli): add export command (#42)`
4. Issues are auto-closed when referenced commit merges to master

### Labels
- `bug` - Something is broken
- `enhancement` - New feature or improvement
- `documentation` - Documentation changes
- `needs-sanitization` - Auto-applied by issue sanitizer

## Development Workflow Checklists

### Feature Development

#### Phase 1: Planning
- [ ] GitHub Issue exists with clear description
- [ ] Architecture decisions made (which module?)
- [ ] Breaking changes identified?

#### Phase 2: Implementation
- [ ] Tests written alongside implementation
- [ ] Code in correct module (cli.py, vault.py, keys.py, etc.)
- [ ] Type hints on all functions
- [ ] Error handling with clear messages

#### Phase 3: Testing
- [ ] Unit tests (pytest)
- [ ] Edge cases tested
- [ ] Coverage >= 70% overall
- [ ] `uv run pytest` passes locally

#### Phase 4: Documentation
- [ ] README.md updated if user-facing
- [ ] CLAUDE.md updated if architectural
- [ ] CHANGELOG.md NOT updated (automatic via semantic-release)

#### Phase 5: Commit & Push
- [ ] Conventional commit message
- [ ] NO Claude attribution
- [ ] Imperative mood
- [ ] CI pipeline green

#### Phase 6: Post-Release
- [ ] Semantic release created automatically
- [ ] Related GitHub Issue closed
- [ ] `uv.lock` synced

### Quick Pre-Commit Checklist

- [ ] No hardcoded secrets/credentials
- [ ] No unused imports
- [ ] No commented-out code
- [ ] Conventional commit format
- [ ] NO Claude attribution
- [ ] Tests pass locally

### Session Start

Run at the beginning of each session:
```bash
uv run python scripts/session_start.py
```

Then review open GitHub issues:
```bash
gh issue list --state open
```
