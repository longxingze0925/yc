#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/apps/ios/Sources/RemoteControllerKit/Infrastructure/BuildServiceConfiguration.swift"
API_URL="${RCTL_OFFICIAL_API_URL:?RCTL_OFFICIAL_API_URL is required}"
SIGNAL_URL="${RCTL_OFFICIAL_SIGNAL_URL:?RCTL_OFFICIAL_SIGNAL_URL is required}"

[[ "$API_URL" =~ ^https://[A-Za-z0-9._:/-]+$ ]] || {
    echo 'RCTL_OFFICIAL_API_URL contains unsupported characters' >&2
    exit 2
}
[[ "$SIGNAL_URL" =~ ^wss://[A-Za-z0-9._:/-]+$ ]] || {
    echo 'RCTL_OFFICIAL_SIGNAL_URL contains unsupported characters' >&2
    exit 2
}

TEMP_FILE="$(mktemp)"
cleanup() {
    rm -f "$TEMP_FILE"
}
trap cleanup EXIT

printf '%s\n' \
    '// Generated during the iOS build. Do not edit endpoint values here.' \
    'enum BuildServiceConfiguration {' \
    "    static let apiURL = \"$API_URL\"" \
    "    static let signalURL = \"$SIGNAL_URL\"" \
    '}' > "$TEMP_FILE"

if [[ ! -f "$TARGET" ]] || ! cmp -s "$TEMP_FILE" "$TARGET"; then
    install -m 0644 "$TEMP_FILE" "$TARGET"
fi

echo "$TARGET"
