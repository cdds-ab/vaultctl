"""Click CLI for vaultctl — Ansible Vault management."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .config import VaultConfig, find_config, load_config
from .keys import (
    ExpiryWarning,
    check_expiry,
    get_key_info,
    load_keys,
    save_keys,
    update_key_metadata,
)
from .password import resolve_password
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
        if ctx.invoked_subcommand == "init":
            ctx.obj = VaultContext(VaultConfig())
            return
        click.echo("Fehler: Keine .vaultctl.yml gefunden.", err=True)
        click.echo("Starte mit 'vaultctl init' oder erstelle eine .vaultctl.yml Konfiguration.", err=True)
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
        click.echo(f"Fehler: {config_path} existiert bereits. Verwende --force zum Überschreiben.", err=True)
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
    click.echo(f"Erstellt: {config_path}")

    if not keys_path.exists():
        dump_yaml({"vault_keys": {}}, keys_path)
        click.echo(f"Erstellt: {keys_path}")

    if not vault_path.exists():
        password = click.prompt("Vault-Passwort", hide_input=True, confirmation_prompt=True)
        encrypt_vault({}, vault_path, password)
        click.echo(f"Erstellt: {vault_path}")
    else:
        click.echo(f"Existiert bereits: {vault_path}")

    click.echo("\nProjekt initialisiert. Nächster Schritt: vaultctl set <key> <value>")


@main.command("list")
@pass_ctx
def list_cmd(vctx: VaultContext) -> None:
    """List all vault keys with descriptions."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    keys_meta = load_keys(vctx.config.keys_file)

    for key in sorted(data.keys()):
        info = get_key_info(keys_meta, key)
        desc = info.description if info else ""
        if desc:
            click.echo(f"  {key:<40}  {desc}")
        else:
            click.echo(f"  {key:<40}  (keine Beschreibung)")


@main.command()
@click.argument("key")
@pass_ctx
def get(vctx: VaultContext, key: str) -> None:
    """Show the value of a vault key."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Fehler: Key '{key}' nicht im Vault gefunden.", err=True)
        sys.exit(1)

    value = data[key]
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
def set(vctx: VaultContext, key: str, value: str | None, use_prompt: bool, from_file: str | None, backup: bool, expires: str | None, force: bool) -> None:
    """Set a vault key."""
    if use_prompt:
        value = click.prompt(f"Wert für {key}", hide_input=True)
        if not value:
            click.echo("Fehler: Leerer Wert.", err=True)
            sys.exit(1)
    elif from_file:
        value = Path(from_file).read_text(encoding="utf-8")
    elif value is None:
        click.echo("Fehler: Kein Wert angegeben. Verwende <value>, --prompt oder --file.", err=True)
        sys.exit(1)

    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    if key in data:
        if data[key] == value:
            click.echo(f"Unverändert: {key} (Wert identisch)")
            return

        if not force:
            click.confirm(f"Key '{key}' existiert bereits. Überschreiben?", abort=True)

        if backup:
            data[f"{key}_previous"] = data[key]
            click.echo(f"Backup: {key}_previous")

    data[key] = value

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    if expires:
        keys_meta = load_keys(vctx.config.keys_file)
        update_key_metadata(keys_meta, key, expires=expires)
        save_keys(keys_meta, vctx.config.keys_file)

    if key in data and f"{key}_previous" in data:
        click.echo(f"Aktualisiert: {key}")
    else:
        click.echo(f"Hinzugefügt: {key}")


@main.command()
@click.argument("key")
@click.option("--force", is_flag=True, default=False, help="Skip confirmation prompts.")
@pass_ctx
def delete(vctx: VaultContext, key: str, force: bool) -> None:
    """Remove a key from the vault."""
    try:
        data = decrypt_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Fehler: Key '{key}' nicht im Vault gefunden.", err=True)
        sys.exit(1)

    if not force:
        click.confirm(f"Key '{key}' wirklich löschen?", abort=True)

    del data[key]

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Gelöscht: {key}")


@main.command()
@click.argument("key")
@pass_ctx
def describe(vctx: VaultContext, key: str) -> None:
    """Show metadata for a vault key."""
    keys_meta = load_keys(vctx.config.keys_file)
    info = get_key_info(keys_meta, key)

    if info is None:
        click.echo(f"Fehler: Keine Metadaten für '{key}'.", err=True)
        known = sorted(keys_meta.keys())
        if known:
            click.echo("\nBekannte Keys:", err=True)
            for k in known:
                click.echo(f"  {k}", err=True)
        sys.exit(1)

    click.echo(f"Key:          {info.name}")
    click.echo(f"Beschreibung: {info.description or '—'}")
    click.echo(f"Rotation:     {info.rotate or '—'}")
    if info.expires:
        click.echo(f"Ablauf:       {info.expires}")
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
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    if previous_key not in data:
        click.echo(f"Fehler: {previous_key} nicht im Vault gefunden.", err=True)
        click.echo("Kein vorheriger Wert zum Wiederherstellen.", err=True)
        sys.exit(1)

    if key not in data:
        click.echo(f"Fehler: {key} nicht im Vault gefunden.", err=True)
        sys.exit(1)

    click.echo(f"Aktuell: {key}")
    click.echo(f"Backup:  {previous_key}")

    if not force:
        click.confirm(f"\n{key} aus {previous_key} wiederherstellen?", abort=True)

    data[key], data[previous_key] = data[previous_key], data[key]

    try:
        encrypt_vault(data, vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Wiederhergestellt: {key}")


@main.command()
@pass_ctx
def edit(vctx: VaultContext) -> None:
    """Open the vault in $EDITOR."""
    try:
        edit_vault(vctx.config.vault_file, vctx.password)
    except VaultError as exc:
        click.echo(f"Fehler: {exc}", err=True)
        sys.exit(1)


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
            click.echo("Keine Keys mit Ablaufdatum konfiguriert.")
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
        label = f"ABGELAUFEN (seit {-w.days_remaining} Tagen)"
    elif w.status == "warning":
        color = "yellow"
        label = f"Warnung ({w.days_remaining} Tage verbleibend)"
    else:
        color = "green"
        label = f"OK ({w.days_remaining} Tage verbleibend)"

    click.echo(f"  {w.key:<40}  {w.expires}  " + click.style(label, fg=color))
