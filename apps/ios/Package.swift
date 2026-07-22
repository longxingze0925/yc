// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "RemoteController",
    defaultLocalization: "zh-Hans",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "RemoteControllerKit", targets: ["RemoteControllerKit"])
    ],
    targets: [
        .target(
            name: "RemoteControllerKit",
            path: "Sources/RemoteControllerKit",
            resources: [.process("Media/Shaders")]
        ),
        .testTarget(
            name: "RemoteControllerKitTests",
            dependencies: ["RemoteControllerKit"],
            path: "Tests/RemoteControllerKitTests"
        )
    ]
)
