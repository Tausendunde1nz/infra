#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec /usr/bin/python3 "${SCRIPT_DIR}/tu1nz_adult_restore_verify.py" "$@"
