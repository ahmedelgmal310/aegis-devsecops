#!/usr/bin/env bash
# Shared helpers for the platform scripts.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${REPORT_DIR:-$ROOT_DIR/reports}"
# shellcheck source=scripts/versions.env
source "$ROOT_DIR/scripts/versions.env"
mkdir -p "$REPORT_DIR"

if [[ -t 1 ]]; then
  BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; RESET=$'\e[0m'
else
  BOLD=""; GREEN=""; RED=""; YELLOW=""; CYAN=""; RESET=""
fi

step() { printf '\n%s==> %s%s\n' "$BOLD$CYAN" "$*" "$RESET"; }
ok()   { printf '  %s✔%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() { printf '  %s✘%s %s\n' "$RED" "$RESET" "$*" >&2; }
die()  { fail "$*"; exit 1; }

require() {
  for bin in "$@"; do
    command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
  done
}

# fetch_verified URL SHA256 DEST: download a manifest and refuse it if the
# checksum does not match the pinned value.
fetch_verified() {
  local url="$1" sha="$2" dest="$3"
  curl -fsSL --retry 3 "$url" -o "$dest"
  echo "$sha  $dest" | sha256sum -c --status - || die "checksum mismatch for $url"
}

# summary appends Markdown to the GitHub job summary when running in CI.
summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
  fi
}
