# Security Architecture

This document explains how vaultctl handles credential data and why its design
prevents secret leakage — even when using optional AI-assisted features.

Target audience: security-conscious DevOps engineers and compliance reviewers.

---

## 1. All Operations Are Local

vaultctl runs entirely on the local machine. There is no cloud service, no
telemetry, no analytics, no phone-home behavior.

- Secrets are decrypted in-process, used, and discarded.
- Encryption and decryption are delegated to `ansible-vault` via subprocess —
  a battle-tested tool maintained by the Ansible project.
- The vault password never leaves the process boundary (see
  [Password Handling](#5-password-and-temporary-file-handling)).

### Metadata vs. Secrets Separation

vaultctl maintains two files with distinct security profiles:

| File | Encrypted | Contains |
|------|-----------|----------|
| `vault.yml` | Yes (AES-256, ansible-vault) | Secret values |
| `vault-keys.yml` | No | Descriptions, rotation schedules, consumers, expiry dates |

This separation is intentional: metadata can be version-controlled and reviewed
without exposing secrets.

---

## 2. Data Flow During Type Detection

When `vaultctl detect-types` runs **without** `--ai`, all processing is local.

### What Is Read

The heuristic engine inspects:

- **Key names** — matched against regex patterns (e.g. `ssh`, `cert`, `password`)
- **Dict field names** — checked against known field-set patterns (e.g.
  `{username, password}` suggests `usernamePassword`)
- **Explicit `type` fields** — extracted verbatim from dict entries
- **Value patterns** — only PEM headers and SSH public key prefixes are matched
  (first few bytes, not the full key material)

### What Is NOT Read or Stored

- Secret values are not logged, cached, or written to any file beyond the
  encrypted vault itself.
- Detection results contain only key names, suggested types, and confidence
  levels — never values.

### Recursive Detection

For nested credential stores, only `item["type"]` string values are extracted
from list items inside dicts. The recursion in `_collect_nested_credential_types()`
walks structure but never captures leaf values.

---

## 3. AI-Assisted Detection: Triple-Layer Protection

When `--ai` is used, vault data must cross a process boundary to reach an
external API. Three independent layers prevent secret leakage, plus a runtime
guard and transport enforcement.

### Layer 1: Redaction (`redact_vault_data()`)

**File:** `src/vaultctl/redact.py`

Before any external processing, all vault data passes through `redact_vault_data()`:

- Every leaf value (strings, integers, booleans) is replaced with the fixed
  placeholder `***REDACTED***`.
- Dict keys are preserved (they are structural metadata, not secrets).
- List lengths are preserved; each element is individually redacted.
- The only exception: `type` field values are preserved (they are classification
  labels, not secrets).

This function is the **security boundary**. It is deterministic, has no
configuration, and cannot be bypassed by payload construction.

### Layer 2: Explicit Field Extraction (`build_payload()`)

**File:** `src/vaultctl/ai_detect.py`

Even after redaction, `build_payload()` does not send the redacted dict as-is.
It constructs a minimal payload through explicit field extraction:

```
For each vault entry:
  - key          (the entry name)
  - fields       (list of dict field names, if the entry is a dict)
  - explicit_type (only if a "type" field exists)
  - value_type   ("string" — for scalar entries)
  - phase1_suggestion (local heuristic result)
  - phase1_confidence (heuristic confidence level)
```

No other data is included. No expiry metadata, no consumer lists, no rotation
schedules.

### Layer 3: Consent Dialog

**File:** `src/vaultctl/cli.py`, function `_run_ai_detection()`

Before any data is sent, the user sees:

1. An explicit list of what will be transmitted
2. The target endpoint URL
3. The model name
4. A SHA-256 hash of the payload (for audit traceability)

The user must confirm with an interactive prompt. This can be pre-approved via
`consent: true` in `.vaultctl.yml` or skipped with `--yes` (for CI pipelines
where the config file itself represents consent).

### Runtime Guard: `contains_unredacted()`

**File:** `src/vaultctl/redact.py`

`contains_unredacted(original, redacted)` compares all original leaf values
against the serialized redacted output. If any original value (longer than 2
characters) appears in the redacted data, it is flagged as a leak. This function
is used in tests to verify redaction correctness.

### HTTPS Enforcement

**File:** `src/vaultctl/ai_detect.py`, function `_validate_endpoint()`

- All remote endpoints must use HTTPS.
- HTTP is allowed **only** for `localhost`, `127.0.0.1`, and `::1` — supporting
  local LLM services (Ollama, vLLM) without TLS overhead.
- Any HTTP endpoint pointing to a non-localhost host is rejected with an error.

### Pre-Flight Inspection: `--show-payload`

Users can run:

```bash
vaultctl detect-types --show-payload
```

This decrypts the vault, builds the redacted payload, prints it to stdout with
its SHA-256 hash, and exits — **without sending anything**. This allows auditing
the exact data that would be transmitted.

---

## 4. Trust Boundaries

### Configuration File (`.vaultctl.yml`)

The config file is the trust boundary. Anyone who can modify `.vaultctl.yml` has
project-level access and can:

- Change the vault/keys file paths
- Configure password resolution commands
- Set AI endpoints and API key commands

This is equivalent to having write access to the project. vaultctl does not
attempt to protect against a compromised config file — that is an infrastructure
security concern, not an application concern.

### Shell Execution (`shell=True`)

Two config fields execute shell commands:

- `password.cmd` — resolves the vault password (e.g. `pass show project/vault`)
- `ai.api_key_cmd` — resolves the AI API key (e.g. `pass show openai/key`)

Both use `shell=True`. This is a deliberate design choice:

1. The commands come from `.vaultctl.yml`, which is trusted input (see above).
2. Users expect shell features (pipes, `pass` integration, `gpg` invocations).
3. Restricting to `shell=False` would require users to write wrapper scripts
   for common password managers — adding complexity without security benefit.

These calls are annotated with `# nosec B602` for Bandit, acknowledging the
conscious decision.

### AI Response Handling

AI responses are treated as **untrusted data**:

- Parsed as JSON string literals only — never evaluated as code.
- Only `key`, `suggested_type`, and `confidence` string fields are extracted.
- Unknown fields are silently dropped.
- Malformed responses result in an empty suggestion list (graceful degradation).

---

## 5. Password and Temporary File Handling

### Password Resolution Chain

The vault password is resolved through a configurable fallback chain:

1. **Environment variable** (`password.env`) — checked first
2. **File** (`password.file`) — read if env var is unset
3. **Command** (`password.cmd`) — executed as last resort

The resolved password is held in memory for the duration of the CLI invocation.
It is never written to disk, logged, or included in error messages.

### Temporary Files

Two types of temporary files are created during operations:

| Purpose | Permissions | Lifetime |
|---------|-------------|----------|
| Password file for `ansible-vault --vault-password-file` | `0600` | Deleted in `finally` block after each vault operation |
| Plaintext YAML for `ansible-vault encrypt` | `0600` | Deleted in `finally` block after encryption completes |

Both use `tempfile.mkstemp()` with explicit `os.fchmod(fd, 0o600)` enforcement
regardless of umask. Cleanup is guaranteed by `finally` blocks — even if
`ansible-vault` crashes or raises an exception.

---

## 6. What Is NEVER Sent to External Services

Even when using `--ai`, the following data categories **never leave the process**:

- Secret values (passwords, tokens, keys, certificates, connection strings)
- Vault passwords
- API keys (resolved locally, sent only in the `Authorization` header to the
  configured endpoint)
- Expiry dates
- Consumer lists
- Rotation schedules or commands
- File paths

What **is** sent (after consent):

- Vault key names (e.g. `db_password`, `ssh_deploy_key`)
- Dict field names (e.g. `username`, `password`, `private_key`)
- Explicit `type` field values (e.g. `usernamePassword`)
- Value type indicators (`"string"` for scalar entries)
- Phase 1 heuristic results (suggested type and confidence)

Key names may reveal infrastructure details (e.g. `prod_database_password`
implies a production database exists). The consent dialog warns about this
explicitly.

---

## 7. Verification

Users can independently verify the security properties described above.

### Inspect the Redacted View

```bash
vaultctl detect-types --show-redacted
```

Shows the full vault structure with all leaf values replaced by
`***REDACTED***`. Confirms that no secrets survive redaction.

### Inspect the AI Payload

```bash
vaultctl detect-types --show-payload
```

Shows the exact JSON payload that would be sent to the AI endpoint, including
the SHA-256 hash. Nothing is transmitted — the command exits after printing.

### Audit the Payload Hash

The SHA-256 hash printed during consent and `--show-payload` is computed over
the canonical JSON representation of the payload entries. Running the same
command twice on an unchanged vault produces the same hash, enabling
reproducibility checks.

### Source Code Audit

The security-relevant code paths are concentrated in four small modules:

| Module | Lines | Responsibility |
|--------|-------|----------------|
| `redact.py` | ~80 | Deterministic value redaction |
| `ai_detect.py` | ~250 | Payload construction, endpoint validation, API call |
| `vault.py` | ~80 | Temp file handling, ansible-vault subprocess |
| `password.py` | ~60 | Password resolution chain |

Total security-critical surface: under 500 lines of Python.
