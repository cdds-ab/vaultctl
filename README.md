# vaultctl

Generalized Ansible Vault management CLI. Manage encrypted secrets with metadata, rotation tracking, and expiry checks.

## Quickstart

```bash
uv tool install .          # or: pip install .
vaultctl init              # create .vaultctl.yml + empty vault
vaultctl list              # list all keys
```

## Installation

```bash
# From source
uv sync
uv run vaultctl --help

# Install as tool
uv tool install .
```

## Configuration

vaultctl looks for `.vaultctl.yml` in this order:

1. `$VAULTCTL_CONFIG` environment variable
2. `.vaultctl.yml` in current directory, then upwards to git root
3. `~/.config/vaultctl/config.yml`

```yaml
# .vaultctl.yml
vault_file: inventory/group_vars/all/vault.yml
keys_file: inventory/group_vars/all/vault-keys.yml

password:
  env: VAULT_PASS                          # Environment variable
  file: ~/.ansible-vault-pass              # File fallback
  cmd: pass show project/vault             # Command fallback
```

All paths are resolved relative to the config file directory.

### Password Resolution

The vault password is resolved using a fallback chain:

1. Environment variable (`password.env`)
2. File (`password.file`)
3. Command (`password.cmd`)

The first source that returns a non-empty value wins. If a source is configured
but yields no result, resolution continues with the next source.

**Empty string is treated as unset:** Setting `VAULT_PASS=""` does *not* provide
a password — it falls through to the file or command source. This is intentional
because an empty password is never valid for `ansible-vault`.

## Commands

### `vaultctl init`

Initialize a new project with config, empty vault, and keys file.

```bash
vaultctl init
vaultctl init --vault-file secrets/vault.yml --keys-file secrets/keys.yml
```

### `vaultctl list`

List all vault keys with descriptions from metadata.

```bash
vaultctl list
```

### `vaultctl get <key>`

Print the value of a vault key.

```bash
vaultctl get my_api_token
vaultctl get my_api_token | pbcopy    # copy to clipboard
```

### `vaultctl set <key> <value>`

Set a vault key. Supports inline value, interactive prompt, or file input.

```bash
vaultctl set my_token "abc123" --force
vaultctl set my_token --prompt
vaultctl set my_ssl_key --file /tmp/key.pem --force
vaultctl set my_token "abc123" --force --expires 2026-12-31
vaultctl set my_token "abc123" --force --no-backup
```

| Flag | Description |
|------|-------------|
| `--force` | Skip confirmation prompts |
| `--prompt` | Enter value interactively (hidden input) |
| `--file PATH` | Read value from file |
| `--backup / --no-backup` | Save previous value as `<key>_previous` (default: backup) |
| `--expires YYYY-MM-DD` | Set expiry date in vault-keys.yml |

### `vaultctl delete <key>`

Remove a key from the vault.

```bash
vaultctl delete old_token --force
```

### `vaultctl describe <key>`

Show metadata for a key from vault-keys.yml.

```bash
vaultctl describe my_api_token
```

### `vaultctl restore <key>`

Restore a key from its `_previous` backup (swap current and previous values).

```bash
vaultctl restore my_api_token --force
```

### `vaultctl edit`

Open the vault in `$EDITOR` via `ansible-vault edit`.

```bash
vaultctl edit
```

### `vaultctl check`

Check for expired or soon-to-expire keys (based on `expires` field in vault-keys.yml).

```bash
vaultctl check                    # default: 30 day warning
vaultctl check --warn-days 90     # 90 day warning threshold
vaultctl check --json             # JSON output for monitoring
vaultctl check --quiet            # only exit code (1 = expired keys)
```

Exit code 1 if any keys are expired (useful in CI/cron).

## Key Metadata (vault-keys.yml)

```yaml
vault_keys:
  my_api_token:
    description: "API token for service X"
    rotate: "365d"
    expires: "2026-12-01"
    consumers: ["host01", "host02"]
    rotate_cmd: "Web UI -> Settings -> Regenerate"
```

| Field | Description |
|-------|-------------|
| `description` | What this secret is for |
| `rotate` | Rotation schedule (e.g. "365d", "manual", "never") |
| `expires` | Expiry date (ISO 8601, optional) |
| `consumers` | Hosts/services using this secret |
| `rotate_cmd` | Instructions for rotation |

## Global Flags

| Flag | Description |
|------|-------------|
| `--config PATH` | Explicit config file path |
| `--vault-file PATH` | Override vault file path |
| `--version` | Show version |

## Requirements

- Python >= 3.13
- `ansible-vault` (from ansible-core) must be in PATH
