"""Click CLI for vaultctl — Ansible Vault management."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from .ai_detect import AIDetectionError, build_payload, call_ai, merge_results, resolve_api_key
from .config import VaultConfig, find_config, load_config
from .detect import DetectionResult, detect_all, filter_by_confidence
from .detection_ops import apply_detected_types
from .keys import (
    ExpiryWarning,
    check_expiry,
    get_key_info,
    import_keys_from_vault,
    load_keys,
    save_keys,
    update_key_metadata,
)
from .password import resolve_password
from .redact import redact_vault_data
from .types import detect_entry_type, get_entry_fields, get_field_value
from .vault import VaultError, decrypt_vault, edit_vault, encrypt_vault
from .yaml_util import dump_yaml


class VaultContext:
    """Shared state passed through Click context."""

    def __init__(self, config: VaultConfig):
        self.config = config
        self._password: str | None = None

    @property
    def password(self) -> str:
        if self._password is None:
            self._password = resolve_password(self.config.password)
        return self._password


pass_ctx = click.make_pass_decorator(VaultContext)


@click.group()
@click.option(
    "--config", "config_path", type=click.Path(exists=True), default=None, help="Path to .vaultctl.yml config file."
)
@click.option("--vault-file", type=click.Path(), default=None, help="Override vault file path.")
@click.version_option(package_name="vaultctl")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, vault_file: str | None) -> None:
    """vaultctl — Ansible Vault management CLI."""
    cfg_path = Path(config_path) if config_path else find_config()

    if cfg_path is None:
        if ctx.invoked_subcommand in ("init", "self-update"):
            ctx.obj = VaultContext(VaultConfig())
            return
        click.echo("Error: No .vaultctl.yml found.", err=True)
        click.echo("Run 'vaultctl init' or create a .vaultctl.yml configuration.", err=True)
        sys.exit(1)

    config = load_config(cfg_path)
    if vault_file:
        config.vault_file = Path(vault_file)
    ctx.obj = VaultContext(config)


@main.command()
@click.option("--vault-file", default="vault.yml", help="Relative path for vault file.")
@click.option("--keys-file", default="vault-keys.yml", help="Relative path for keys metadata file.")
@click.option("--force", is_flag=True, default=False, help="Overwrite existing config.")
@pass_ctx
def init(_vctx: VaultContext, vault_file: str, keys_file: str, force: bool) -> None:
    """Initialize a new vaultctl project."""
    config_path = Path.cwd() / ".vaultctl.yml"
    if config_path.exists() and not force:
        click.echo(f"Error: {config_path} already exists. Use --force to overwrite.", err=True)
        sys.exit(1)

    vault_path = Path.cwd() / vault_file
    keys_path = Path.cwd() / keys_file

    import yaml

    config_data = {
        "vault_file": vault_file,
        "keys_file": keys_file,
        "password": {
            "env": "VAULT_PASS",
            "file": "~/.ansible-vault-pass",
        },
    }
    config_path.write_text(
        yaml.dump(config_data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    click.echo(f"Created: {config_path}")

    if not keys_path.exists():
        dump_yaml({"vault_keys": {}}, keys_path)
        click.echo(f"Created: {keys_path}")

    if not vault_path.exists():
        password = click.prompt("Vault password", hide_input=True, confirmation_prompt=True)
        encrypt_vault({}, vault_path, password)
        click.echo(f"Created: {vault_path}")
        click.echo("\nProject initialized. Next step: vaultctl set <key> <value>")
    else:
        click.echo(f"Existing vault found: {vault_path}")
        _import_existing_vault(vault_path, keys_path)


def _import_existing_vault(vault_path: Path, keys_path: Path) -> None:
    """Import an existing vault: generate metadata skeleton and detect types."""
    password = click.prompt("Vault password", hide_input=True)
    try:
        data = decrypt_vault(vault_path, password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        return

    # Filter out _previous backup keys for the summary
    real_keys = [k for k in sorted(data) if not k.endswith("_previous")]
    click.echo(f"Found {len(real_keys)} keys in vault.")

    if not real_keys:
        return

    # Import keys into metadata
    keys = load_keys(keys_path)
    keys, new_count = import_keys_from_vault(data, keys)

    if new_count:
        save_keys(keys, keys_path)
        click.echo(f"Added {new_count} keys to {keys_path.name}.")

    # Run type detection (local heuristics only, no secrets leave the process)
    results = detect_all(data)
    detected = [r for r in results if not r.skipped and r.suggested_type != "secretText"]
    if detected:
        click.echo("\nDetected types:")
        for r in detected:
            click.echo(f"  {r.key:<40} → {r.suggested_type} ({r.confidence})")

        if click.confirm("\nApply detected types to metadata?", default=True):
            for r in detected:
                keys = update_key_metadata(keys, r.key, type=r.suggested_type)
            save_keys(keys, keys_path)
            click.echo("Types applied.")

    click.echo("\nImport complete. Run 'vaultctl list' to see your keys.")
    click.echo("Fill in descriptions: vaultctl describe <key>")


@main.command("list")
@pass_ctx
def list_cmd(vctx: VaultContext) -> None:
    """List all vault keys with descriptions."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    keys_meta = load_keys(vctx.config.keys_file)

    for key in sorted(data.keys()):
        info = get_key_info(keys_meta, key)
        desc = info.description if info else ""
        entry_type = detect_entry_type(data[key])
        type_tag = f"[{entry_type}] " if entry_type != "secretText" else ""
        if desc:
            click.echo(f"  {key:<40}  {type_tag}{desc}")
        else:
            click.echo(f"  {key:<40}  {type_tag}(no description)")


@main.command()
@click.argument("key")
@click.option("--field", default=None, help="Access a specific field of a structured entry.")
@pass_ctx
def get(vctx: VaultContext, key: str, field: str | None) -> None:
    """Show the value of a vault key."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Error: Key '{key}' not found in vault.", err=True)
        sys.exit(1)

    value = data[key]

    if field:
        try:
            click.echo(get_field_value(value, field))
        except KeyError as exc:
            click.echo(f"Error: {exc}", err=True)
            sys.exit(1)
        return

    entry_type = detect_entry_type(value)
    if isinstance(value, dict):
        click.echo(f"Type: {entry_type}")
        for f in get_entry_fields(value):
            click.echo(f"  {f}: {value[f]}")
    else:
        click.echo(value, nl=not isinstance(value, str) or not value.endswith("\n"))


@main.command()
@click.argument("key")
@click.argument("value", required=False)
@click.option("--prompt", "use_prompt", is_flag=True, help="Enter value interactively.")
@click.option("--file", "from_file", type=click.Path(exists=True), help="Read value from file.")
@click.option("--backup/--no-backup", default=True, help="Save previous value as <key>_previous.")
@click.option("--expires", default=None, help="Expiry date (YYYY-MM-DD) for vault-keys.yml.")
@click.option("--force", is_flag=True, default=False, help="Skip confirmation prompts.")
@pass_ctx
def set(
    vctx: VaultContext,
    key: str,
    value: str | None,
    use_prompt: bool,
    from_file: str | None,
    backup: bool,
    expires: str | None,
    force: bool,
) -> None:
    """Set a vault key."""
    value = _resolve_set_value(value, use_prompt, from_file, key)

    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if key in data:
        if data[key] == value:
            click.echo(f"Unchanged: {key} (value identical)")
            return

        if not force:
            click.confirm(f"Key '{key}' already exists. Overwrite?", abort=True)

        if backup:
            data[f"{key}_previous"] = data[key]
            click.echo(f"Backup: {key}_previous")

    data[key] = value

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if expires:
        keys_meta = load_keys(vctx.config.keys_file)
        update_key_metadata(keys_meta, key, expires=expires)
        save_keys(keys_meta, vctx.config.keys_file)

    if key in data and f"{key}_previous" in data:
        click.echo(f"Updated: {key}")
    else:
        click.echo(f"Added: {key}")


@main.command()
@click.argument("key")
@click.option("--force", is_flag=True, default=False, help="Skip confirmation prompts.")
@pass_ctx
def delete(vctx: VaultContext, key: str, force: bool) -> None:
    """Remove a key from the vault."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Error: Key '{key}' not found in vault.", err=True)
        sys.exit(1)

    if not force:
        click.confirm(f"Delete key '{key}'?", abort=True)

    del data[key]

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Deleted: {key}")


@main.command()
@click.argument("key")
@pass_ctx
def describe(vctx: VaultContext, key: str) -> None:
    """Show metadata for a vault key."""
    keys_meta = load_keys(vctx.config.keys_file)
    info = get_key_info(keys_meta, key)

    if info is None:
        click.echo(f"Error: No metadata for '{key}'.", err=True)
        known = sorted(keys_meta.keys())
        if known:
            click.echo("\nKnown keys:", err=True)
            for k in known:
                click.echo(f"  {k}", err=True)
        sys.exit(1)

    click.echo(f"Key:          {info.name}")
    if info.entry_type:
        click.echo(f"Type:         {info.entry_type}")
    click.echo(f"Description:  {info.description or '—'}")
    click.echo(f"Rotation:     {info.rotate or '—'}")
    if info.expires:
        click.echo(f"Expires:      {info.expires}")
    if info.consumers:
        click.echo(f"Consumers:    {info.consumers[0]}")
        for c in info.consumers[1:]:
            click.echo(f"              {c}")
    if info.rotate_cmd:
        click.echo(f"Rotate cmd:   {info.rotate_cmd}")


@main.command()
@click.argument("key")
@click.option("--force", is_flag=True, default=False, help="Skip confirmation prompts.")
@pass_ctx
def restore(vctx: VaultContext, key: str, force: bool) -> None:
    """Restore a key from its _previous backup."""
    previous_key = f"{key}_previous"

    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if previous_key not in data:
        click.echo(f"Error: {previous_key} not found in vault.", err=True)
        click.echo("No previous value to restore.", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Error: {key} not found in vault.", err=True)
        sys.exit(1)

    click.echo(f"Current: {key}")
    click.echo(f"Backup: {previous_key}")

    if not force:
        click.confirm(f"\nRestore {key} from {previous_key}?", abort=True)

    data[key], data[previous_key] = data[previous_key], data[key]

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Restored: {key}")


@main.command()
@pass_ctx
def edit(vctx: VaultContext) -> None:
    """Open the vault in $EDITOR."""
    try:
        edit_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@main.command("detect-types")
@click.option("--apply", is_flag=True, default=False, help="Write detected types to vault and keys file.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option(
    "--confidence",
    type=click.Choice(["high", "medium", "low"]),
    default="low",
    help="Minimum confidence level to display (default: low).",
)
@click.option("--show-redacted", is_flag=True, default=False, help="Show redacted vault structure (audit/debug).")
@click.option("--ai", is_flag=True, default=False, help="Use AI-assisted detection (requires ai: config).")
@click.option("--show-payload", is_flag=True, default=False, help="Show the redacted AI payload without sending.")
@click.option("--yes", is_flag=True, default=False, help="Skip AI consent prompt (for CI/automation).")
@pass_ctx
def detect_types(
    vctx: VaultContext,
    apply: bool,
    as_json: bool,
    confidence: str,
    show_redacted: bool,
    ai: bool,
    show_payload: bool,
    yes: bool,
) -> None:
    """Detect entry types using heuristics (key names, structure, value patterns)."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if show_redacted:
        redacted = redact_vault_data(data)
        click.echo(json.dumps(redacted, indent=2, default=str))
        return

    # Phase 1: local heuristics (always runs)
    results = detect_all(data)

    # Phase 2: AI-assisted detection (optional)
    if ai or show_payload:
        results = _run_ai_detection(vctx, data, results, show_payload, yes)

    # Filter by confidence
    results = filter_by_confidence(results, confidence)  # type: ignore[arg-type]

    actionable = [r for r in results if not r.skipped]

    if as_json:
        _print_detection_json(results)
    else:
        _print_detection_table(results)

    if apply and actionable:
        keys_meta = load_keys(vctx.config.keys_file)
        try:
            result = apply_detected_types(
                actionable, data, keys_meta, vctx.config.vault_file, vctx.config.keys_file, vctx.password
            )
        except VaultError as exc:
            click.echo(f"Error writing vault: {exc}", err=True)
            sys.exit(1)
        click.echo(f"\nApplied types to {result.applied_count} entries.")
    elif apply:
        click.echo("\nNothing to apply — all entries already typed or secretText.")


def _format_detection_result(r: DetectionResult) -> str:
    """Format a single detection result as a colored line."""
    if r.skipped:
        return f"  {r.key:<40}  {click.style('skip', fg='cyan')}  ({', '.join(r.signals)})"
    conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(r.confidence, "white")
    line = (
        f"  {r.key:<40}  {r.suggested_type:<20}  "
        + click.style(r.confidence, fg=conf_color)
        + f"  ({', '.join(r.signals)})"
    )
    if r.sub_types:
        summary = ", ".join(f"{c}x {t}" for t, c in sorted(r.sub_types.items(), key=lambda x: -x[1]))
        line += f"\n    contains: {summary}"
    return line


def _print_detection_table(results: list[DetectionResult]) -> None:
    """Print detection results as a formatted table."""
    if not results:
        click.echo("No entries to analyze.")
        return
    for r in results:
        click.echo(_format_detection_result(r))


def _print_detection_json(results: list[DetectionResult]) -> None:
    """Print detection results as JSON."""
    items = [
        {
            "key": r.key,
            "current_type": r.current_type,
            "suggested_type": r.suggested_type,
            "confidence": r.confidence,
            "signals": r.signals,
            "skipped": r.skipped,
            **({"sub_types": r.sub_types} if r.sub_types else {}),
        }
        for r in results
    ]
    click.echo(json.dumps(items, indent=2))


def _resolve_set_value(value: str | None, use_prompt: bool, from_file: str | None, key: str) -> str:
    """Resolve the value for a set operation from the three input modes.

    Returns the resolved value string.  Calls ``sys.exit(1)`` if no value
    can be determined.
    """
    if use_prompt:
        resolved: str = click.prompt(f"Value for {key}", hide_input=True)
        if not resolved:
            click.echo("Error: Empty value.", err=True)
            sys.exit(1)
        return resolved
    if from_file:
        return Path(from_file).read_text(encoding="utf-8")
    if value is None:
        click.echo("Error: No value provided. Use <value>, --prompt or --file.", err=True)
        sys.exit(1)
    return value


def _run_ai_detection(
    vctx: VaultContext,
    data: dict[str, Any],
    phase1_results: list[Any],
    show_payload: bool,
    skip_consent: bool,
) -> list[Any]:
    """Run AI-assisted detection with consent flow and exception firewall."""
    ai_config = vctx.config.ai

    payload = build_payload(data, phase1_results, ai_config)

    if show_payload:
        click.echo("Redacted payload that would be sent to AI:\n")
        click.echo(json.dumps(payload.redacted_data, indent=2))
        click.echo(f"\nPayload hash: {payload.payload_hash}")
        click.echo(f"Endpoint:     {payload.endpoint or '(not configured)'}")
        click.echo(f"Model:        {payload.model or '(not configured)'}")
        sys.exit(0)

    # GDPR consent check
    if not ai_config.consent and not skip_consent:
        click.echo("AI-assisted detection sends the following data to an external service:")
        click.echo("  - Vault key names (may reveal infrastructure details)")
        click.echo("  - Entry structure (field names, nesting)")
        click.echo("  - Phase 1 heuristic results")
        click.echo("  - NO secret values (all redacted)")
        click.echo(f"\n  Endpoint: {ai_config.endpoint or '(not configured)'}")
        click.echo(f"  Model:    {ai_config.model or '(not configured)'}")
        click.echo(f"  Payload hash: {payload.payload_hash}")
        if not click.confirm("\nProceed with AI classification?"):
            click.echo("Aborted. Using local heuristics only.")
            return phase1_results

    # Exception firewall: no vault data in error messages
    try:
        api_key = resolve_api_key(ai_config.api_key_cmd)
        ai_suggestions = call_ai(payload, api_key)
        return merge_results(phase1_results, ai_suggestions)
    except AIDetectionError as exc:
        click.echo(f"AI detection failed: {exc}", err=True)
        click.echo("Falling back to local heuristics.", err=True)
        return phase1_results


@main.command()
@click.option("--warn-days", default=30, type=int, help="Warning threshold in days (default: 30).")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--quiet", is_flag=True, help="Only exit code, no output.")
@pass_ctx
def check(vctx: VaultContext, warn_days: int, as_json: bool, quiet: bool) -> None:
    """Check for expired or soon-to-expire keys."""
    keys_meta = load_keys(vctx.config.keys_file)
    warnings = check_expiry(keys_meta, warn_days=warn_days)

    if not warnings:
        if not quiet:
            click.echo("No keys with expiry date configured.")
        return

    has_expired = any(w.status == "expired" for w in warnings)

    if as_json:
        if not quiet:
            items = [
                {
                    "key": w.key,
                    "expires": w.expires.isoformat(),
                    "days_remaining": w.days_remaining,
                    "status": w.status,
                }
                for w in warnings
            ]
            click.echo(json.dumps(items, indent=2))
    elif not quiet:
        for w in warnings:
            _print_expiry_warning(w)

    if has_expired:
        sys.exit(1)


def _print_expiry_warning(w: ExpiryWarning) -> None:
    """Print a single expiry warning with color."""
    if w.status == "expired":
        color = "red"
        label = f"EXPIRED ({-w.days_remaining} days ago)"
    elif w.status == "warning":
        color = "yellow"
        label = f"Warning ({w.days_remaining} days remaining)"
    else:
        color = "green"
        label = f"OK ({w.days_remaining} days remaining)"

    click.echo(f"  {w.key:<40}  {w.expires}  " + click.style(label, fg=color))


@main.command("self-update")
@pass_ctx
def self_update_cmd(_vctx: VaultContext) -> None:
    """Update vaultctl to the latest version (standalone binaries only)."""
    from .self_update import UpdateError, is_frozen, self_update

    if is_frozen():
        current = getattr(sys, "_MEIPASS_VERSION", None) or __import__("vaultctl").__version__
    else:
        from importlib.metadata import version as pkg_version

        current = pkg_version("vaultctl")

    click.echo(f"Current version: {current}")
    click.echo("Checking for updates...")

    try:
        new_version = self_update(current)
    except UpdateError as exc:
        click.echo(f"Update failed: {exc}", err=True)
        sys.exit(1)

    if new_version:
        click.echo(f"Updated to {new_version}.")
    else:
        click.echo("Already up to date.")
