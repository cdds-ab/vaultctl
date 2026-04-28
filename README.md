# vaultctl

[![CI](https://github.com/cdds-ab/vaultctl/actions/workflows/ci.yml/badge.svg)](https://github.com/cdds-ab/vaultctl/actions/workflows/ci.yml)
[![Release](https://github.com/cdds-ab/vaultctl/releases/latest/badge.svg)](https://github.com/cdds-ab/vaultctl/releases/latest)

A CLI for managing Ansible Vault secrets — with metadata tracking, expiry monitoring, type detection, and self-updating standalone binaries.

## Install

```bash
# Download standalone binary (no Python required)
curl -fsSL https://github.com/cdds-ab/vaultctl/releases/latest/download/vaultctl-linux-amd64 -o vaultctl
chmod +x vaultctl
```

<details>
<summary>Alternative: install from source (requires Python >= 3.13)</summary>

```bash
uv sync && uv run vaultctl --help
# or: pip install .
```
</details>

### Required external tools

vaultctl shells out to external binaries that must be installed separately:

- **`ansible-vault`** — handles the actual encryption/decryption.
  Install via your distro package manager or `pip install ansible-core`.
- **`cue`** *(optional, for schema validation — see [#34](https://github.com/cdds-ab/vaultctl/issues/34))* —
  enables future `vaultctl validate` and schema-checked imports.
  Install: <https://cuelang.org/docs/install/>.
  vaultctl gracefully skips schema features when `cue` is not on `$PATH`.

## Quickstart: New Vault

```bash
vaultctl init
vaultctl set db_password --prompt --expires 2026-12-31
vaultctl list
```

## Import Existing Vault

Already have an Ansible Vault? Point `init` at it — vaultctl scans the vault locally, generates a metadata skeleton, and auto-detects entry types. No secrets leave the process.

```bash
vaultctl init --vault-file inventory/group_vars/all/vault.yml
# → enters vault password
# → scans keys, detects types (usernamePassword, sshKey, certificate, ...)
# → generates vault-keys.yml with all entries
# → asks to apply detected types
```

After import, fill in descriptions and rotation schedules:

```bash
vaultctl describe my_api_token        # see current metadata
vaultctl check                        # which keys need attention?
```

## Commands

| Command | Description |
|---------|-------------|
| `vaultctl init` | New vault or import existing (auto-detects types) |
| `vaultctl list` | List all keys (shows `[type]` tags for structured entries) |
| `vaultctl get <key>` | Print secret value (`--field name` for structured entries) |
| `vaultctl set <key> [value]` | Set a key (`--prompt`, `--file`, `--expires`, `--no-backup`) |
| `vaultctl delete <key>` | Remove a key |
| `vaultctl describe <key>` | Show metadata (rotation, consumers, expiry) |
| `vaultctl restore <key>` | Swap current value with `_previous` backup |
| `vaultctl edit` | Open vault in `$EDITOR` via `ansible-vault edit` |
| `vaultctl check` | Report expired/expiring keys (`--json`, `--quiet`, `--warn-days N`) |
| `vaultctl detect-types` | Auto-detect entry types (`--apply`, `--ai`, `--show-redacted`) |
| `vaultctl validate` | Validate config, metadata, and vault content against CUE schemas |
| `vaultctl schema infer` | Generate a CUE schema baseline from current vault content |
| `vaultctl schema sync` | Detect drift between baseline and current vault (`--apply` to update) |
| `vaultctl self-update` | Update binary to latest release (standalone only) |

All mutating commands support `--force` to skip confirmation prompts.

## Configuration

vaultctl looks for `.vaultctl/config.yml` in: `$VAULTCTL_CONFIG` → current directory upwards to git root → `~/.config/vaultctl/config.yml`.

```yaml
# .vaultctl/config.yml
vault_file: inventory/group_vars/all/vault.yml
keys_file: inventory/group_vars/all/vault-keys.yml

password:
  env: VAULT_PASS              # tried first
  file: ~/.ansible-vault-pass  # then file
  cmd: pass show project/vault # then command
```

Paths resolve relative to the project root (the parent of `.vaultctl/`), so vault and keys files live where Ansible expects them — typically next to your inventory data, not inside `.vaultctl/` itself.

## Key Metadata

Secret metadata lives in `vault-keys.yml` (unencrypted, separate from secrets):

```yaml
vault_keys:
  my_api_token:
    description: "API token for service X"
    rotate: "365d"
    expires: "2026-12-01"
    consumers: ["host01", "host02"]
    rotate_cmd: "Web UI → Settings → Regenerate"
```

`vaultctl check` uses the `expires` field to flag expired or soon-to-expire credentials — exit code 1 for CI/cron integration.

## Schema Validation

`vaultctl validate` checks your project against CUE schemas — typo detection, type constraints, cross-file consistency. Useful as a CI gate or pre-commit hook.

```bash
vaultctl validate                # full check: config, metadata, vault, cross-consistency
vaultctl validate --skip-content # skip vault content (no decryption needed)
```

**What it checks:**

- `.vaultctl/config.yml` against the bundled `#Config` schema (catches typos like `pasword:`).
- `vault-keys.yml` against the bundled `#KeysFile` schema (rejects unknown fields, invalid types like `bogusType`, malformed `expires` dates).
- `vault.yml` content against the bundled `#VaultFile` schema (permissive by default — strings or structured objects).
- Cross-file consistency: every key in `vault.yml` has metadata in `vault-keys.yml` and vice versa (`_previous` backup keys exempt).

**Custom schemas:**

Drop your own CUE schema next to the config to override the bundled defaults — keeps strict, project-specific rules close to the data.

```
.vaultctl/
├── config.yml
├── vault.cue              # overrides #VaultFile (e.g. require min password length)
├── vault.constraints.cue  # additional constraints; CUE merges with vault.cue
└── keys.cue               # overrides #KeysFile (e.g. require descriptions)
```

**Bootstrap from existing data:**

```bash
vaultctl schema infer       # writes .vaultctl/vault.cue covering the current vault
vaultctl schema infer --force   # overwrites an existing baseline
```

The generated baseline is a closed `#VaultFile` definition — adding a new key without re-running `infer` (or extending the schema by hand) makes `validate` fail. Hand-edited rules (regex constraints, value ranges, required descriptions) belong in a sibling `vault.constraints.cue` so subsequent `infer` runs don't trample them.

**Detect drift between vault and baseline:**

```bash
vaultctl schema sync           # diff-only, exit 1 on drift — CI-friendly
vaultctl schema sync --apply   # rewrite the baseline to match the vault
```

`schema sync` re-derives the schema from the current vault content and compares it to `.vaultctl/vault.cue`. Without `--apply` it prints a unified diff and exits non-zero; with `--apply` it rewrites the baseline. `vault.constraints.cue` is never touched — CUE merges it back in at validation time.

**Without `cue` installed:** schema checks are skipped with a warning; the cross-consistency check still runs.

## Type Detection

vaultctl can auto-detect structured entry types (`usernamePassword`, `sshKey`, `certificate`, `secretText`) from field structure, value patterns, and key names:

```bash
vaultctl detect-types              # dry-run: show suggestions
vaultctl detect-types --apply      # write types to vault-keys.yml
vaultctl detect-types --ai --yes   # use AI-assisted detection (GDPR consent required)
```

AI detection sends only redacted metadata (key names, field names) — no secret values leave the process.

## Self-Update

Standalone binaries update themselves with SHA256 checksum verification:

```bash
vaultctl self-update
```

Downgrades are prevented. Updates without published checksums are refused.

## Troubleshooting

**"Decryption failed (no vault secrets were found that could decrypt)"**

vaultctl cannot find or resolve the vault password. Check your `.vaultctl/config.yml`:

```yaml
password:
  env: VAULT_PASS              # set this env var, or
  file: ~/.ansible-vault-pass  # point to a password file, or
  cmd: pass show project/vault # run a command that prints the password
```

At least one source must be configured. The chain is tried top to bottom — first match wins.

**"No config file found"**

vaultctl searches for `.vaultctl/config.yml` upwards from the current directory. Run `vaultctl init` to create one, or set `VAULTCTL_CONFIG=/path/to/config.yml`.

**`vaultctl init` overwrites my password config**

`init` creates a fresh `.vaultctl/config.yml` with defaults. If you re-run `init` in a directory that already has a config, the password section resets. Edit `.vaultctl/config.yml` manually after init to add your password source.

**`self-update` says "only available for standalone binaries"**

You installed via `pip` or `uv tool install`, not the standalone binary. Update with:

```bash
uv tool install --force --from git+ssh://git@github.com/cdds-ab/vaultctl.git vaultctl
```

## Security

vaultctl is designed to handle credential data safely. All operations run locally, secrets never leave the process, and AI-assisted features use triple-layer redaction before any external communication.

For a detailed security analysis — covering data flow, trust boundaries, temporary file handling, and verification steps — see [docs/SECURITY.md](docs/SECURITY.md).

## License

MIT
