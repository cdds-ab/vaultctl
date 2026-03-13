#!/usr/bin/env bash
# Check cyclomatic complexity — fails on CC grade D or worse.
set -euo pipefail

output=$(uv run radon cc src/vaultctl -n C --no-assert --total-average)
echo "$output"

if echo "$output" | grep -qE ' - [D-F]$'; then
    echo ""
    echo "ERROR: Functions with CC grade D or worse detected. Refactor to reduce complexity."
    exit 1
fi
