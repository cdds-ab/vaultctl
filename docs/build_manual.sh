#!/usr/bin/env bash
# Build docs/manual.pdf from docs/manual.md.
#
# Tooling: pandoc + xelatex. Both are available on most Linux distributions
# via the system package manager (`pandoc`, `texlive-xetex`, plus the Noto and
# DejaVu font packages). All settings (fonts, layout, classoptions) live in
# the YAML metadata block at the top of manual.md — no separate template.

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

pandoc manual.md \
    --pdf-engine=xelatex \
    --highlight-style=tango \
    --output=manual.pdf

echo "Built: $(pwd)/manual.pdf"
