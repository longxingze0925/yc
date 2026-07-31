#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS_DIR="${ROOT}/apps/ios"
OUTPUT_DIR="${IOS_OUTPUT_DIR:-${ROOT}/artifacts/ios-testflight}"
BUILD_NUMBER="${BUILD_NUMBER:-1}"
MARKETING_VERSION="${MARKETING_VERSION:-0.1.0}"
UPLOAD_TO_TESTFLIGHT="${UPLOAD_TO_TESTFLIGHT:-false}"

require_env() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "missing required environment variable: ${name}" >&2
        exit 2
    fi
}

for name in \
    APPLE_TEAM_ID \
    IOS_BUNDLE_ID \
    RCTL_OFFICIAL_API_URL \
    RCTL_OFFICIAL_SIGNAL_URL \
    IOS_DISTRIBUTION_CERTIFICATE_BASE64 \
    IOS_DISTRIBUTION_CERTIFICATE_PASSWORD \
    IOS_PROVISIONING_PROFILE_BASE64 \
    ASC_KEY_ID \
    ASC_ISSUER_ID \
    ASC_PRIVATE_KEY_BASE64; do
    require_env "${name}"
done

for command_name in awk cargo cp ditto find openssl rustup security shasum xcodebuild xcodegen xcrun; do
    command -v "${command_name}" >/dev/null || {
        echo "missing required command: ${command_name}" >&2
        exit 2
    }
done

[[ "${RCTL_OFFICIAL_API_URL}" == https://* ]] || {
    echo "RCTL_OFFICIAL_API_URL must use https" >&2
    exit 2
}
[[ "${RCTL_OFFICIAL_SIGNAL_URL}" == wss://* ]] || {
    echo "RCTL_OFFICIAL_SIGNAL_URL must use wss" >&2
    exit 2
}
[[ "${IOS_BUNDLE_ID}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]+[A-Za-z0-9]$ ]] || {
    echo "IOS_BUNDLE_ID has an invalid format" >&2
    exit 2
}
[[ "${BUILD_NUMBER}" =~ ^[1-9][0-9]*$ ]] || {
    echo "BUILD_NUMBER must be a positive integer" >&2
    exit 2
}
[[ "${MARKETING_VERSION}" =~ ^[0-9]+([.][0-9]+){1,2}$ ]] || {
    echo "MARKETING_VERSION must look like 1.0 or 1.0.0" >&2
    exit 2
}
[[ "${UPLOAD_TO_TESTFLIGHT}" == "true" || "${UPLOAD_TO_TESTFLIGHT}" == "false" ]] || {
    echo "UPLOAD_TO_TESTFLIGHT must be true or false" >&2
    exit 2
}

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/remote-ios-signing.XXXXXX")"
KEYCHAIN_PATH="${TEMP_DIR}/build.keychain-db"
KEYCHAIN_PASSWORD="$(openssl rand -hex 24)"
CERTIFICATE_PATH="${TEMP_DIR}/distribution.p12"
PROFILE_PATH="${TEMP_DIR}/distribution.mobileprovision"
PROFILE_PLIST="${TEMP_DIR}/profile.plist"
EXPORT_OPTIONS="${TEMP_DIR}/ExportOptions.plist"
ARCHIVE_PATH="${TEMP_DIR}/RemoteController.xcarchive"
EXPORT_PATH="${TEMP_DIR}/export"
ASC_KEY_DIRECTORY="${HOME}/private_keys"
ASC_KEY_PATH="${ASC_KEY_DIRECTORY}/AuthKey_${ASC_KEY_ID}.p8"
INSTALLED_PROFILE=""
ASC_KEY_INSTALLED=false
PROFILE_INSTALLED=false

cleanup() {
    if [[ "${PROFILE_INSTALLED}" == "true" ]]; then
        rm -f "${INSTALLED_PROFILE}"
    fi
    if [[ "${ASC_KEY_INSTALLED}" == "true" ]]; then
        rm -f "${ASC_KEY_PATH}"
    fi
    security delete-keychain "${KEYCHAIN_PATH}" >/dev/null 2>&1 || true
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

[[ ! -e "${ASC_KEY_PATH}" ]] || {
    echo "refusing to overwrite existing App Store Connect key: ${ASC_KEY_PATH}" >&2
    exit 2
}

printf '%s' "${IOS_DISTRIBUTION_CERTIFICATE_BASE64}" | /usr/bin/base64 -D >"${CERTIFICATE_PATH}"
printf '%s' "${IOS_PROVISIONING_PROFILE_BASE64}" | /usr/bin/base64 -D >"${PROFILE_PATH}"
mkdir -p "${ASC_KEY_DIRECTORY}"
printf '%s' "${ASC_PRIVATE_KEY_BASE64}" | /usr/bin/base64 -D >"${ASC_KEY_PATH}"
ASC_KEY_INSTALLED=true
chmod 600 "${CERTIFICATE_PATH}" "${PROFILE_PATH}" "${ASC_KEY_PATH}"

security create-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
security set-keychain-settings -lut 21600 "${KEYCHAIN_PATH}"
security unlock-keychain -p "${KEYCHAIN_PASSWORD}" "${KEYCHAIN_PATH}"
security import "${CERTIFICATE_PATH}" \
    -k "${KEYCHAIN_PATH}" \
    -P "${IOS_DISTRIBUTION_CERTIFICATE_PASSWORD}" \
    -A \
    -t cert \
    -f pkcs12
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s \
    -k "${KEYCHAIN_PASSWORD}" \
    "${KEYCHAIN_PATH}"
security list-keychains -d user -s "${KEYCHAIN_PATH}"
IDENTITY_COUNT="$(security find-identity -v -p codesigning "${KEYCHAIN_PATH}" | awk '/valid identities found/ { print $1 }')"
[[ "${IDENTITY_COUNT:-0}" -gt 0 ]] || {
    echo "the imported certificate does not contain a code-signing identity" >&2
    exit 2
}

security cms -D -i "${PROFILE_PATH}" >"${PROFILE_PLIST}"
PROFILE_UUID="$(/usr/libexec/PlistBuddy -c 'Print :UUID' "${PROFILE_PLIST}")"
PROFILE_NAME="$(/usr/libexec/PlistBuddy -c 'Print :Name' "${PROFILE_PLIST}")"
PROFILE_TEAM_ID="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "${PROFILE_PLIST}")"
PROFILE_APPLICATION_ID="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "${PROFILE_PLIST}")"

[[ "${PROFILE_TEAM_ID}" == "${APPLE_TEAM_ID}" ]] || {
    echo "provisioning profile Team ID does not match APPLE_TEAM_ID" >&2
    exit 2
}
[[ "${PROFILE_APPLICATION_ID}" == "${APPLE_TEAM_ID}.${IOS_BUNDLE_ID}" ]] || {
    echo "provisioning profile does not match IOS_BUNDLE_ID" >&2
    exit 2
}

mkdir -p "${HOME}/Library/MobileDevice/Provisioning Profiles"
INSTALLED_PROFILE="${HOME}/Library/MobileDevice/Provisioning Profiles/${PROFILE_UUID}.mobileprovision"
[[ ! -e "${INSTALLED_PROFILE}" ]] || {
    echo "refusing to overwrite existing provisioning profile: ${INSTALLED_PROFILE}" >&2
    exit 2
}
cp "${PROFILE_PATH}" "${INSTALLED_PROFILE}"
PROFILE_INSTALLED=true

"${ROOT}/tools/build-ios-core-xcframework.sh"
(
    cd "${IOS_DIR}"
    xcodegen generate
)

xcodebuild \
    -project "${IOS_DIR}/RemoteController.xcodeproj" \
    -scheme RemoteControllerApp \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -archivePath "${ARCHIVE_PATH}" \
    DEVELOPMENT_TEAM="${APPLE_TEAM_ID}" \
    PRODUCT_BUNDLE_IDENTIFIER="${IOS_BUNDLE_ID}" \
    CODE_SIGN_STYLE=Manual \
    CODE_SIGN_IDENTITY='Apple Distribution' \
    PROVISIONING_PROFILE_SPECIFIER="${PROFILE_NAME}" \
    CURRENT_PROJECT_VERSION="${BUILD_NUMBER}" \
    MARKETING_VERSION="${MARKETING_VERSION}" \
    RCTL_OFFICIAL_API_URL="${RCTL_OFFICIAL_API_URL}" \
    RCTL_OFFICIAL_SIGNAL_URL="${RCTL_OFFICIAL_SIGNAL_URL}" \
    archive

/usr/libexec/PlistBuddy -c 'Add :method string app-store-connect' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c "Add :teamID string ${APPLE_TEAM_ID}" "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :signingStyle string manual' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :signingCertificate string Apple Distribution' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :manageAppVersionAndBuildNumber bool false' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :stripSwiftSymbols bool true' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :uploadSymbols bool true' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c 'Add :provisioningProfiles dict' "${EXPORT_OPTIONS}"
/usr/libexec/PlistBuddy -c "Add :provisioningProfiles:${IOS_BUNDLE_ID} string ${PROFILE_NAME}" "${EXPORT_OPTIONS}"

xcodebuild \
    -exportArchive \
    -archivePath "${ARCHIVE_PATH}" \
    -exportPath "${EXPORT_PATH}" \
    -exportOptionsPlist "${EXPORT_OPTIONS}"

IPA_PATH="$(find "${EXPORT_PATH}" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
[[ -n "${IPA_PATH}" ]] || {
    echo "xcodebuild did not produce an IPA" >&2
    exit 1
}

mkdir -p "${OUTPUT_DIR}"
IPA_OUTPUT="RemoteController-${MARKETING_VERSION}-${BUILD_NUMBER}.ipa"
DSYM_OUTPUT="RemoteController-${MARKETING_VERSION}-${BUILD_NUMBER}-dSYMs.zip"
cp "${IPA_PATH}" "${OUTPUT_DIR}/${IPA_OUTPUT}"
ditto -c -k --keepParent "${ARCHIVE_PATH}/dSYMs" "${OUTPUT_DIR}/${DSYM_OUTPUT}"
(
    cd "${OUTPUT_DIR}"
    shasum -a 256 "${IPA_OUTPUT}" "${DSYM_OUTPUT}" >SHA256SUMS
)

xcrun altool \
    --validate-app \
    --file "${IPA_PATH}" \
    --type ios \
    --apiKey "${ASC_KEY_ID}" \
    --apiIssuer "${ASC_ISSUER_ID}"

if [[ "${UPLOAD_TO_TESTFLIGHT}" == "true" ]]; then
    xcrun altool \
        --upload-app \
        --file "${IPA_PATH}" \
        --type ios \
        --apiKey "${ASC_KEY_ID}" \
        --apiIssuer "${ASC_ISSUER_ID}"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## iOS archive"
        echo
        echo "- Version: ${MARKETING_VERSION} (${BUILD_NUMBER})"
        echo "- Bundle ID: ${IOS_BUNDLE_ID}"
        echo "- TestFlight upload: ${UPLOAD_TO_TESTFLIGHT}"
        echo "- SHA-256: recorded in SHA256SUMS artifact"
    } >>"${GITHUB_STEP_SUMMARY}"
fi

echo "signed iOS artifacts: ${OUTPUT_DIR}"
