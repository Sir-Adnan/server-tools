#!/usr/bin/env bash
# ============================================================================
# tests/smoke.sh — fast sanity checks that need no root and no network:
# the build succeeds, the output parses, and --version/--help behave.
# ============================================================================
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT_DIR}/dist/server-tools.sh"
VERSION="$(tr -d '[:space:]' <"${ROOT_DIR}/VERSION")"

fail() {
  printf 'smoke: FAIL — %s\n' "$1" >&2
  exit 1
}

# Invoke via bash so the test never depends on the exec bit surviving checkout.
bash "${ROOT_DIR}/build.sh" >/dev/null

bash -n "$DIST" || fail "dist does not parse"

if grep -q $'\r' "$DIST"; then
  fail "dist contains CRLF line endings"
fi

out="$(bash "$DIST" --version)"
[[ $out == *"$VERSION"* ]] || fail "--version output '${out}' does not contain '${VERSION}'"

bash "$DIST" --help >/dev/null || fail "--help exited non-zero"

if bash "$DIST" --definitely-not-an-option >/dev/null 2>&1; then
  fail "unknown option should exit non-zero"
fi

if bash "$DIST" --auto --profile >/dev/null 2>&1; then
  fail "--profile without a value should exit non-zero"
fi

bash "$DIST" --help | grep -q -- '--auto' || fail "--help should document --auto"
bash "$DIST" --help | grep -q -- '--dry-run' || fail "--help should document --dry-run"
bash "$DIST" --help | grep -q -- '--report' || fail "--help should document --report"

printf 'smoke: OK (v%s)\n' "$VERSION"
