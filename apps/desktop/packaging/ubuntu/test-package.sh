#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rctl-deb-test.XXXXXX")"
FIXTURE_BINARY="$TEST_ROOT/remote-desktop"
OUTPUT_DIR="$TEST_ROOT/output"
CONTROL_DIR="$TEST_ROOT/control"
DATA_DIR="$TEST_ROOT/data"

cleanup() {
    rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

printf '%s\n' '#!/bin/sh' 'exit 0' > "$FIXTURE_BINARY"
chmod 0755 "$FIXTURE_BINARY"

PACKAGE_PATH="$({
    RCTL_DESKTOP_BINARY="$FIXTURE_BINARY" \
    RCTL_OUTPUT_DIR="$OUTPUT_DIR" \
    RCTL_SKIP_RUNTIME_CHECK=1 \
        "$REPO_ROOT/tools/ubuntu-mobile-mvp.sh" package
} | awk -F': ' '/^Package: / { print $2 }')"

[[ -f "$PACKAGE_PATH" ]] || {
    echo "package was not created: $PACKAGE_PATH" >&2
    exit 1
}

[[ "$(dpkg-deb -f "$PACKAGE_PATH" Package)" == "rctl-remote-desktop" ]]
[[ "$(dpkg-deb -f "$PACKAGE_PATH" Architecture)" == "amd64" ]]

CONTENTS="$(dpkg-deb --contents "$PACKAGE_PATH")"
for expected in \
    ./usr/bin/rctl-remote-desktop \
    ./usr/lib/rctl-remote-desktop/remote-desktop \
    ./usr/lib/systemd/user/rctl-remote-desktop.service \
    ./usr/share/applications/rctl-remote-desktop.desktop \
    ./etc/xdg/autostart/rctl-remote-desktop.desktop \
    ./usr/share/man/man1/rctl-remote-desktop.1.gz \
    ./usr/share/metainfo/com.rctl.RemoteControl.metainfo.xml \
    ./usr/share/pixmaps/rctl-remote-desktop.png \
    ./usr/share/rctl-remote-desktop/certificates/yc-root-ca.crt
do
    grep -Fq "$expected" <<< "$CONTENTS"
done

dpkg-deb --control "$PACKAGE_PATH" "$CONTROL_DIR"
[[ -x "$CONTROL_DIR/postinst" ]]
[[ -x "$CONTROL_DIR/prerm" ]]
grep -Fq 'rctl-remote-desktop-yc-root-ca.crt' "$CONTROL_DIR/postinst"
grep -Fq 'rctl-remote-desktop-yc-root-ca.crt' "$CONTROL_DIR/prerm"
grep -Fxq '/etc/xdg/autostart/rctl-remote-desktop.desktop' "$CONTROL_DIR/conffiles"

dpkg-deb --extract "$PACKAGE_PATH" "$DATA_DIR"
cmp \
    "$REPO_ROOT/artifacts/server-deployment/yc-root-ca.crt" \
    "$DATA_DIR/usr/share/rctl-remote-desktop/certificates/yc-root-ca.crt"

while IFS= read -r mode_and_path; do
    [[ "$mode_and_path" == 755\ * ]]
done < <(find "$DATA_DIR" -type d -printf '%m %p\n')

echo "Ubuntu package structure test passed: $PACKAGE_PATH"
