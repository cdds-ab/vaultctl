#!/usr/bin/env bash
# Build docs/manual.pdf from docs/manual.md.
#
# Tooling: pandoc + xelatex. Both are available on most Linux distributions
# via the system package manager (`pandoc`, `texlive-xetex`, plus the Noto and
# DejaVu font packages). All settings (fonts, layout, classoptions) live in
# the YAML metadata block at the top of manual.md — no separate template.
#
# The vaultctl version is read from ../pyproject.toml at build time and
# injected into the manual's subtitle, so the rendered PDF always carries
# the version it documents.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v pandoc >/dev/null 2>&1; then
    echo "Error: pandoc is not on PATH." >&2
    exit 1
fi
if ! command -v xelatex >/dev/null 2>&1; then
    echo "Error: xelatex is not on PATH (install texlive-xetex)." >&2
    exit 1
fi

# Extract `version = "X.Y.Z"` from the [project] section of pyproject.toml.
VERSION="$(grep -E '^version\s*=' ../pyproject.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "${VERSION}" ]]; then
    echo "Error: could not extract version from ../pyproject.toml" >&2
    exit 1
fi

pandoc manual.md \
    --pdf-engine=xelatex \
    --highlight-style=tango \
    --metadata=subtitle:"User Manual · vaultctl v${VERSION}" \
    --output=manual.pdf

echo "Built: $(pwd)/manual.pdf (vaultctl v${VERSION})"
