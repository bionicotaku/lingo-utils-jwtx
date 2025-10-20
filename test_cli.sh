#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

if ! command -v go >/dev/null 2>&1; then
  echo "go command not found in PATH" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "env file not found: ${ENV_FILE}" >&2
  exit 1
fi

echo "using env file: ${ENV_FILE}"

set -a
source "${ENV_FILE}"
set +a

cd "${SCRIPT_DIR}"

echo "== Google Identity Token validation =="
go run ./cmd/google-validate
echo

echo "== Supabase JWT validation =="
go run ./cmd/supabase-validate
