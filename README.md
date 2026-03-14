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
| `vaultctl self-update` | Update binary to latest release (standalone only) |

All mutating commands support `--force` to skip confirmation prompts.

## Configuration

vaultctl looks for `.vaultctl.yml` in: `$VAULTCTL_CONFIG` → current directory upwards to git root → `~/.config/vaultctl/config.yml`.

```yaml
vault_file: inventory/group_vars/all/vault.yml
keys_file: inventory/group_vars/all/vault-keys.yml

password:
  env: VAULT_PASS              # tried first
  file: ~/.ansible-vault-pass  # then file
  cmd: pass show project/vault # then command
```

All paths resolve relative to the config file.

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

vaultctl cannot find or resolve the vault password. Check your `.vaultctl.yml`:

```yaml
password:
  env: VAULT_PASS              # set this env var, or
  file: ~/.ansible-vault-pass  # point to a password file, or
  cmd: pass show project/vault # run a command that prints the password
```

At least one source must be configured. The chain is tried top to bottom — first match wins.

**"No config file found"**

vaultctl searches for `.vaultctl.yml` upwards from the current directory. Run `vaultctl init` to create one, or set `VAULTCTL_CONFIG=/path/to/.vaultctl.yml`.

**`vaultctl init` overwrites my password config**

`init` creates a fresh `.vaultctl.yml` with defaults. If you re-run `init` in a directory that already has a config, the password section resets. Edit `.vaultctl.yml` manually after init to add your password source.

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
