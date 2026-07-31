#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT}/target/ios-core"
OUTPUT="${ROOT}/apps/ios/Frameworks/RemoteIOSFFI.xcframework"
HEADER_DIR="${ROOT}/crates/remote-ios-ffi/include"

command -v cargo >/dev/null
command -v rustup >/dev/null
command -v xcodebuild >/dev/null
command -v lipo >/dev/null

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build --release -p remote-ios-ffi --target aarch64-apple-ios
cargo build --release -p remote-ios-ffi --target aarch64-apple-ios-sim
cargo build --release -p remote-ios-ffi --target x86_64-apple-ios

mkdir -p "${BUILD_DIR}"
lipo -create \
    "${ROOT}/target/aarch64-apple-ios-sim/release/libremote_ios_ffi.a" \
    "${ROOT}/target/x86_64-apple-ios/release/libremote_ios_ffi.a" \
    -output "${BUILD_DIR}/libremote_ios_ffi_sim.a"

rm -rf "${OUTPUT}"
mkdir -p "$(dirname "${OUTPUT}")"
xcodebuild -create-xcframework \
    -library "${ROOT}/target/aarch64-apple-ios/release/libremote_ios_ffi.a" \
    -headers "${HEADER_DIR}" \
    -library "${BUILD_DIR}/libremote_ios_ffi_sim.a" \
    -headers "${HEADER_DIR}" \
    -output "${OUTPUT}"

echo "${OUTPUT}"
