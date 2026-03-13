# vaultctl

[![CI](https://github.com/cdds-ab/vaultctl/actions/workflows/ci.yml/badge.svg)](https://github.com/cdds-ab/vaultctl/actions/workflows/ci.yml)
[![Release](https://github.com/cdds-ab/vaultctl/releases/latest/badge.svg)](https://github.com/cdds-ab/vaultctl/releases/latest)

A CLI for managing Ansible Vault secrets — with metadata tracking, expiry monitoring, type detection, and self-updating standalone binaries.

## Quickstart

```bash
# Download standalone binary (no Python required)
curl -fsSL https://github.com/cdds-ab/vaultctl/releases/latest/download/vaultctl-linux-amd64 -o vaultctl
chmod +x vaultctl

# Initialize and start managing secrets
./vaultctl init
./vaultctl set db_password --prompt --expires 2026-12-31
./vaultctl list
```

<details>
<summary>Alternative: install from source</summary>

```bash
uv sync && uv run vaultctl --help
# or
pip install .
```

Requires Python >= 3.13 and `ansible-vault` in PATH.
</details>

## Commands

| Command | Description |
|---------|-------------|
| `vaultctl init` | Create `.vaultctl.yml`, empty vault, and keys file |
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

## License

MIT
