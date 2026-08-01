#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="${RCTL_REPOSITORY:-longxingze0925/yc}"
readonly SOURCE_REF="${RCTL_SOURCE_REF:-main}"
readonly MANAGER_URL="${RCTL_MANAGER_URL:-https://raw.githubusercontent.com/${REPOSITORY}/${SOURCE_REF}/ops/remotectl.sh}"

tmp_file="$(mktemp)"
cleanup() {
    rm -f -- "$tmp_file"
}
trap cleanup EXIT INT TERM

printf 'Downloading remote-control deployment manager from %s\n' "$MANAGER_URL"
curl --fail --silent --show-error --location "$MANAGER_URL" --output "$tmp_file"
grep -q '^RCTL_MANAGER_VERSION=' "$tmp_file" \
    || { printf 'Downloaded manager failed the format check\n' >&2; exit 1; }
chmod 0700 "$tmp_file"

bash "$tmp_file" install "$@"
