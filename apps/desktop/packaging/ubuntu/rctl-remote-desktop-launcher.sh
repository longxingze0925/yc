#!/bin/sh
set -eu

if command -v systemctl >/dev/null 2>&1 \
    && systemctl --user show-environment >/dev/null 2>&1; then
    systemctl --user start --no-block rctl-remote-desktop.service
    exit 0
fi

exec /usr/lib/rctl-remote-desktop/remote-desktop "$@"
