#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_DIR="$ROOT/apps/ios"
OUTPUT_DIR="${IOS_OUTPUT_DIR:-$ROOT/artifacts/ios-unsigned}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
MARKETING_VERSION="${MARKETING_VERSION:-0.1.0}"
IOS_BUNDLE_ID="${IOS_BUNDLE_ID:-com.rctl.remote.controller}"

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || {
        echo "missing required environment variable: $name" >&2
        exit 2
    }
}

require_env RCTL_OFFICIAL_API_URL
require_env RCTL_OFFICIAL_SIGNAL_URL

[[ "$RCTL_OFFICIAL_API_URL" == https://* ]] || {
    echo 'RCTL_OFFICIAL_API_URL must use https' >&2
    exit 2
}
[[ "$RCTL_OFFICIAL_SIGNAL_URL" == wss://* ]] || {
    echo 'RCTL_OFFICIAL_SIGNAL_URL must use wss' >&2
    exit 2
}
[[ "$IOS_BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+[A-Za-z0-9]$ ]] || {
    echo 'IOS_BUNDLE_ID has an invalid format' >&2
    exit 2
}
[[ "$BUILD_NUMBER" =~ ^[1-9][0-9]*$ ]] || {
    echo 'BUILD_NUMBER must be a positive integer' >&2
    exit 2
}
[[ "$MARKETING_VERSION" =~ ^[0-9]+([.][0-9]+){1,2}$ ]] || {
    echo 'MARKETING_VERSION must look like 1.0 or 1.0.0' >&2
    exit 2
}

for command_name in cargo ditto find lipo plutil rustup shasum xcodebuild xcodegen zip; do
    command -v "$command_name" >/dev/null || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/remote-ios-unsigned.XXXXXX")"
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

"$ROOT/tools/build-ios-core-xcframework.sh"
(
    cd "$IOS_DIR"
    xcodegen generate
)

DERIVED_DATA="$TEMP_DIR/DerivedData"
xcodebuild \
    -project "$IOS_DIR/RemoteController.xcodeproj" \
    -scheme RemoteControllerApp \
    -configuration Release \
    -sdk iphoneos \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY= \
    PRODUCT_BUNDLE_IDENTIFIER="$IOS_BUNDLE_ID" \
    CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
    MARKETING_VERSION="$MARKETING_VERSION" \
    RCTL_OFFICIAL_API_URL="$RCTL_OFFICIAL_API_URL" \
    RCTL_OFFICIAL_SIGNAL_URL="$RCTL_OFFICIAL_SIGNAL_URL" \
    build

APP_PATH="$(find "$DERIVED_DATA/Build/Products/Release-iphoneos" \
    -maxdepth 1 -type d -name '*.app' -print -quit)"
[[ -n "$APP_PATH" && -f "$APP_PATH/Info.plist" ]] || {
    echo 'xcodebuild did not produce an iPhone app bundle' >&2
    exit 1
}

[[ "$(/usr/libexec/PlistBuddy -c 'Print :RCTLOfficialAPIURL' "$APP_PATH/Info.plist")" \
    == "$RCTL_OFFICIAL_API_URL" ]]
[[ "$(/usr/libexec/PlistBuddy -c 'Print :RCTLOfficialSignalURL' "$APP_PATH/Info.plist")" \
    == "$RCTL_OFFICIAL_SIGNAL_URL" ]]
plutil -lint "$APP_PATH/Info.plist" >/dev/null

PACKAGE_DIR="$TEMP_DIR/package"
mkdir -p "$PACKAGE_DIR/Payload" "$OUTPUT_DIR"
ditto "$APP_PATH" "$PACKAGE_DIR/Payload/$(basename "$APP_PATH")"

IPA_NAME="RemoteController-${MARKETING_VERSION}-${BUILD_NUMBER}-unsigned.ipa"
(
    cd "$PACKAGE_DIR"
    zip -qry "$OUTPUT_DIR/$IPA_NAME" Payload
)
(
    cd "$OUTPUT_DIR"
    shasum -a 256 "$IPA_NAME" > SHA256SUMS
)

echo "unsigned iPhone IPA: $OUTPUT_DIR/$IPA_NAME"
