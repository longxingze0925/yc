#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-package}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
MANIFEST_PATH="$REPO_ROOT/apps/desktop/Cargo.toml"
PACKAGING_DIR="$REPO_ROOT/apps/desktop/packaging/ubuntu"
OUTPUT_DIR="${RCTL_OUTPUT_DIR:-$REPO_ROOT/artifacts/ubuntu-mobile-mvp}"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/apps/desktop/target}"
BUILT_BINARY="$TARGET_DIR/release/remote-desktop"
PACKAGE_NAME="rctl-remote-desktop"
PACKAGE_ARCH="amd64"
CA_CERT_PATH="${RCTL_CA_CERT_PATH:-$REPO_ROOT/artifacts/server-deployment/yc-root-ca.crt}"
EXPECTED_CA_SHA256="8686e04a66e3978e5c5f8c11d0d5bf9afcc44b6fbe2e19277ead05481895cbc8"

usage() {
    cat <<'EOF'
Usage: tools/ubuntu-mobile-mvp.sh [check|build|stage|package]

Modes:
  check    Validate the Ubuntu host, package templates, and runtime plugins.
  build    Build the release desktop binary with the official service endpoints.
  stage    Create an unpacked Debian filesystem tree without root privileges.
  package  Build an unsigned internal-test .deb and SHA-256 checksum (default).

Release builds require:
  RCTL_OFFICIAL_API_URL       HTTPS API URL
  RCTL_OFFICIAL_SIGNAL_URL    WSS Signal URL
  RCTL_OFFICIAL_RELAY_URL     Relay HOST:PORT

Set RCTL_DESKTOP_BINARY to package an existing executable without rebuilding.
Set RCTL_OUTPUT_DIR to change the output directory.
The internal package embeds artifacts/server-deployment/yc-root-ca.crt and
adds that exact CA to the Ubuntu system trust store while the package is installed.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

validate_host() {
    [[ "$(uname -s)" == "Linux" ]] || die "this script only supports Linux"
    [[ "$(uname -m)" == "x86_64" ]] || die "Ubuntu Mobile MVP packages require x86_64"
    [[ "$(dpkg --print-architecture)" == "$PACKAGE_ARCH" ]] \
        || die "dpkg architecture must be $PACKAGE_ARCH"

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "26.04" ]] \
            || die "this internal package must be built on Ubuntu 26.04"
    fi
}

validate_templates() {
    local file
    for file in \
        rctl-remote-desktop.desktop \
        rctl-remote-desktop-autostart.desktop \
        rctl-remote-desktop.service \
        rctl-remote-desktop-launcher.sh \
        com.rctl.RemoteControl.metainfo.xml \
        copyright \
        postinst \
        prerm \
        rctl-remote-desktop.1 \
        rctl-remote-desktop.png
    do
        [[ -s "$PACKAGING_DIR/$file" ]] || die "missing packaging file: $file"
    done

    desktop-file-validate "$PACKAGING_DIR/rctl-remote-desktop.desktop"
    desktop-file-validate "$PACKAGING_DIR/rctl-remote-desktop-autostart.desktop"
    local systemd_output
    if ! systemd_output="$(
        systemd-analyze --user verify "$PACKAGING_DIR/rctl-remote-desktop.service" 2>&1
    )"; then
        if grep -Eq \
            '^rctl-remote-desktop\.service:.*(Unknown key|Unknown lvalue|Failed to parse|Invalid argument)' \
            <<< "$systemd_output"; then
            printf '%s\n' "$systemd_output" >&2
            die "systemd user unit validation failed"
        fi
        echo "warning: systemd semantic verification unavailable in this environment" >&2
    fi
    appstreamcli validate --no-net "$PACKAGING_DIR/com.rctl.RemoteControl.metainfo.xml"
}

validate_ca_certificate() {
    [[ -s "$CA_CERT_PATH" ]] || die "missing internal-test CA certificate: $CA_CERT_PATH"
    local actual_sha256
    actual_sha256="$(sha256sum "$CA_CERT_PATH" | awk '{print $1}')"
    [[ "$actual_sha256" == "$EXPECTED_CA_SHA256" ]] \
        || die "internal-test CA certificate checksum does not match the deployed server CA"
    openssl x509 -in "$CA_CERT_PATH" -noout -checkend 0 >/dev/null \
        || die "internal-test CA certificate is invalid or expired"
    openssl verify -CAfile "$CA_CERT_PATH" "$CA_CERT_PATH" >/dev/null \
        || die "internal-test CA certificate is not self-verifiable"
}

validate_runtime() {
    [[ "${RCTL_SKIP_RUNTIME_CHECK:-0}" == "1" ]] && return

    require_command gst-launch-1.0
    require_command gst-inspect-1.0
    local plugin
    for plugin in fdsrc rawvideoparse videoconvert x264enc multipartmux fdsink; do
        gst-inspect-1.0 "$plugin" >/dev/null 2>&1 \
            || die "missing required GStreamer plugin: $plugin"
    done
    pkg-config --exists libpipewire-0.3 \
        || die "missing PipeWire development files (libpipewire-0.3-dev)"
}

cleanup_package_staging() {
    if [[ -n "${STAGING_ROOT:-}" && -d "$STAGING_ROOT" ]]; then
        rm -rf -- "$STAGING_ROOT"
    fi
}

validate_endpoints() {
    : "${RCTL_OFFICIAL_API_URL:?RCTL_OFFICIAL_API_URL is required}"
    : "${RCTL_OFFICIAL_SIGNAL_URL:?RCTL_OFFICIAL_SIGNAL_URL is required}"
    : "${RCTL_OFFICIAL_RELAY_URL:?RCTL_OFFICIAL_RELAY_URL is required}"

    [[ "$RCTL_OFFICIAL_API_URL" == https://* ]] \
        || die "RCTL_OFFICIAL_API_URL must use https"
    [[ "$RCTL_OFFICIAL_SIGNAL_URL" == wss://* ]] \
        || die "RCTL_OFFICIAL_SIGNAL_URL must use wss"
    [[ "$RCTL_OFFICIAL_API_URL" != *[[:space:]]* \
        && "$RCTL_OFFICIAL_SIGNAL_URL" != *[[:space:]]* \
        && "$RCTL_OFFICIAL_RELAY_URL" != *[[:space:]]* ]] \
        || die "service endpoints must not contain whitespace"
    [[ "$RCTL_OFFICIAL_RELAY_URL" =~ ^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):([0-9]{1,5})$ ]] \
        || die "RCTL_OFFICIAL_RELAY_URL must use HOST:PORT"
    local relay_port="${BASH_REMATCH[2]}"
    (( relay_port >= 1 && relay_port <= 65535 )) \
        || die "RCTL_OFFICIAL_RELAY_URL port is outside 1..65535"
}

package_version() {
    local upstream_version revision
    upstream_version="$(
        cargo metadata \
            --manifest-path "$MANIFEST_PATH" \
            --format-version 1 \
            --no-deps \
        | jq -r '.packages[] | select(.name == "remote-desktop") | .version'
    )"
    [[ -n "$upstream_version" && "$upstream_version" != "null" ]] \
        || die "could not read desktop package version"
    revision="${RCTL_PACKAGE_REVISION:-1~mobilemvp+git$(git -C "$REPO_ROOT" rev-parse --short=8 HEAD)}"
    if [[ -z "${RCTL_PACKAGE_REVISION:-}" ]] \
        && [[ -n "$(git -C "$REPO_ROOT" status --porcelain)" ]]; then
        revision="${revision}+dirty"
    fi
    printf '%s-%s\n' "$upstream_version" "$revision"
}

build_binary() {
    if [[ -n "${RCTL_DESKTOP_BINARY:-}" ]]; then
        [[ -x "$RCTL_DESKTOP_BINARY" ]] \
            || die "RCTL_DESKTOP_BINARY is not executable: $RCTL_DESKTOP_BINARY"
        printf '%s\n' "$RCTL_DESKTOP_BINARY"
        return
    fi

    validate_endpoints
    if ! cargo build \
        --manifest-path "$MANIFEST_PATH" \
        --target-dir "$TARGET_DIR" \
        --release \
        --locked; then
        die "release build failed; refusing to package an existing binary"
    fi
    [[ -x "$BUILT_BINARY" ]] || die "release build did not create $BUILT_BINARY"
    printf '%s\n' "$BUILT_BINARY"
}

create_control_file() {
    local staging_root="$1"
    local version="$2"
    cat > "$staging_root/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $version
Section: net
Priority: optional
Architecture: $PACKAGE_ARCH
Maintainer: Remote Control Project <longxingze0925@users.noreply.github.com>
Depends: ca-certificates, gstreamer1.0-tools, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good, gstreamer1.0-plugins-ugly, libc6 (>= 2.38), libfontconfig1, libgcc-s1, libpipewire-0.3-0, pipewire, systemd, xdg-desktop-portal
Recommends: xdg-desktop-portal-gnome | xdg-desktop-portal-kde
Description: account-based remote desktop client (internal test)
 Desktop client used to register this Ubuntu computer and allow explicitly
 enabled remote access from another device on the same account.
EOF
}

create_changelog() {
    local staging_root="$1"
    local version="$2"
    local commit_epoch
    commit_epoch="$(git -C "$REPO_ROOT" show -s --format=%ct HEAD)"
    cat > "$staging_root/usr/share/doc/$PACKAGE_NAME/changelog.Debian" <<EOF
$PACKAGE_NAME ($version) unstable; urgency=medium

  * Build the Ubuntu 26.04 x86_64 Mobile MVP internal test package.

 -- Remote Control Project <longxingze0925@users.noreply.github.com>  $(date -R -d "@$commit_epoch")
EOF
    gzip -n -9 "$staging_root/usr/share/doc/$PACKAGE_NAME/changelog.Debian"
}

create_staging_tree() {
    local binary="$1"
    local staging_root="$2"
    local version="$3"

    install -d -m 0755 \
        "$staging_root/DEBIAN" \
        "$staging_root/etc/xdg/autostart" \
        "$staging_root/usr/bin" \
        "$staging_root/usr/lib/rctl-remote-desktop" \
        "$staging_root/usr/lib/systemd/user" \
        "$staging_root/usr/share/applications" \
        "$staging_root/usr/share/doc/$PACKAGE_NAME" \
        "$staging_root/usr/share/man/man1" \
        "$staging_root/usr/share/metainfo" \
        "$staging_root/usr/share/pixmaps" \
        "$staging_root/usr/share/rctl-remote-desktop/certificates"

    install -m 0755 "$binary" \
        "$staging_root/usr/lib/rctl-remote-desktop/remote-desktop"
    if file "$staging_root/usr/lib/rctl-remote-desktop/remote-desktop" \
        | grep -q 'ELF .* executable'; then
        strip --strip-unneeded "$staging_root/usr/lib/rctl-remote-desktop/remote-desktop"
    fi
    install -m 0755 "$PACKAGING_DIR/rctl-remote-desktop-launcher.sh" \
        "$staging_root/usr/bin/rctl-remote-desktop"
    install -m 0644 "$PACKAGING_DIR/rctl-remote-desktop.service" \
        "$staging_root/usr/lib/systemd/user/rctl-remote-desktop.service"
    install -m 0644 "$PACKAGING_DIR/rctl-remote-desktop.desktop" \
        "$staging_root/usr/share/applications/rctl-remote-desktop.desktop"
    install -m 0644 "$PACKAGING_DIR/rctl-remote-desktop-autostart.desktop" \
        "$staging_root/etc/xdg/autostart/rctl-remote-desktop.desktop"
    install -m 0644 "$PACKAGING_DIR/com.rctl.RemoteControl.metainfo.xml" \
        "$staging_root/usr/share/metainfo/com.rctl.RemoteControl.metainfo.xml"
    install -m 0644 "$PACKAGING_DIR/rctl-remote-desktop.png" \
        "$staging_root/usr/share/pixmaps/rctl-remote-desktop.png"
    install -m 0644 "$PACKAGING_DIR/copyright" \
        "$staging_root/usr/share/doc/$PACKAGE_NAME/copyright"
    gzip -n -9 -c "$PACKAGING_DIR/rctl-remote-desktop.1" \
        > "$staging_root/usr/share/man/man1/rctl-remote-desktop.1.gz"
    chmod 0644 "$staging_root/usr/share/man/man1/rctl-remote-desktop.1.gz"
    install -m 0644 "$CA_CERT_PATH" \
        "$staging_root/usr/share/rctl-remote-desktop/certificates/yc-root-ca.crt"
    install -m 0755 "$PACKAGING_DIR/postinst" "$staging_root/DEBIAN/postinst"
    install -m 0755 "$PACKAGING_DIR/prerm" "$staging_root/DEBIAN/prerm"
    printf '%s\n' '/etc/xdg/autostart/rctl-remote-desktop.desktop' \
        > "$staging_root/DEBIAN/conffiles"
    create_changelog "$staging_root" "$version"
    chmod 0644 "$staging_root/usr/share/doc/$PACKAGE_NAME/changelog.Debian.gz"
    create_control_file "$staging_root" "$version"
    find "$staging_root" -type d -exec chmod 0755 {} +
}

run_check() {
    require_command appstreamcli
    require_command cargo
    require_command desktop-file-validate
    require_command dpkg
    require_command dpkg-deb
    require_command git
    require_command gzip
    require_command install
    require_command jq
    require_command openssl
    require_command pkg-config
    require_command sha256sum
    require_command strip
    require_command systemd-analyze
    validate_host
    validate_templates
    validate_ca_certificate
    validate_runtime
}

case "$MODE" in
    -h|--help|help)
        usage
        exit 0
        ;;
    check)
        run_check
        echo "Ubuntu packaging checks passed."
        ;;
    build)
        run_check
        BINARY="$(build_binary)"
        echo "Binary: $BINARY"
        ;;
    stage|package)
        run_check
        BINARY="$(build_binary)"
        VERSION="$(package_version)"
        mkdir -p "$OUTPUT_DIR"
        STAGING_ROOT="$(mktemp -d "$OUTPUT_DIR/staging.XXXXXX")"
        if [[ "$MODE" == "package" ]]; then
            trap cleanup_package_staging EXIT
        fi
        create_staging_tree "$BINARY" "$STAGING_ROOT" "$VERSION"

        if [[ "$MODE" == "stage" ]]; then
            echo "Staging: $STAGING_ROOT"
            exit 0
        fi

        PACKAGE_PATH="$OUTPUT_DIR/${PACKAGE_NAME}_${VERSION}_${PACKAGE_ARCH}.deb"
        dpkg-deb --root-owner-group --build "$STAGING_ROOT" "$PACKAGE_PATH" >/dev/null
        (
            cd "$OUTPUT_DIR"
            sha256sum "${PACKAGE_PATH##*/}"
        ) > "$PACKAGE_PATH.sha256"
        dpkg-deb --info "$PACKAGE_PATH" >/dev/null
        dpkg-deb --contents "$PACKAGE_PATH" >/dev/null
        echo "Package: $PACKAGE_PATH"
        echo "Checksum: $PACKAGE_PATH.sha256"
        ;;
    *)
        usage >&2
        die "unsupported mode: $MODE"
        ;;
esac
