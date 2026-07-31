// swift-tools-version: 5.9

import PackageDescription
import Foundation

let ffiFrameworkPath = "Frameworks/RemoteIOSFFI.xcframework"
let packageDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let ffiAvailable = FileManager.default.fileExists(
    atPath: packageDirectory.appendingPathComponent(ffiFrameworkPath).path
)
var controllerDependencies: [Target.Dependency] = []
var controllerSwiftSettings: [SwiftSetting] = []
var packageTargets: [Target] = []

if ffiAvailable {
    packageTargets.append(.binaryTarget(name: "RemoteIOSFFI", path: ffiFrameworkPath))
    controllerDependencies.append(.target(name: "RemoteIOSFFI"))
    controllerSwiftSettings.append(.define("REMOTE_CORE_FFI"))
}

packageTargets.append(.target(
    name: "RemoteControllerKit",
    dependencies: controllerDependencies,
    path: "Sources/RemoteControllerKit",
    resources: [
        .process("Media/Shaders"),
        .process("PrivacyInfo.xcprivacy")
    ],
    swiftSettings: controllerSwiftSettings
))
packageTargets.append(.testTarget(
    name: "RemoteControllerKitTests",
    dependencies: ["RemoteControllerKit"],
    path: "Tests/RemoteControllerKitTests"
))

let package = Package(
    name: "RemoteController",
    defaultLocalization: "zh-Hans",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "RemoteControllerKit", targets: ["RemoteControllerKit"])
    ],
    targets: packageTargets
)
