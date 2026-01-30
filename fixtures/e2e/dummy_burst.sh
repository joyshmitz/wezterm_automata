#!/bin/bash
# Dummy burst script for stress testing
# Emits COUNT lines as fast as possible with a marker.
#
# Usage: ./dummy_burst.sh [COUNT] [MARKER]

set -euo pipefail

COUNT="${1:-100000}"
MARKER="${2:-E2E_STRESS_MARKER}"

for i in $(seq 1 "$COUNT"); do
    printf "Line %d: %s\n" "$i" "$MARKER"
done
