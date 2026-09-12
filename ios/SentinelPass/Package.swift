// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SentinelPass",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .executable(
            name: "SentinelPassApp",
            targets: ["SentinelPassApp"]
        ),
    ],
    dependencies: [],
    targets: [
        // Native C library target: module.modulemap + include/sentinelpass_bridge.h.
        // The header is a copy of the generated contract under
        // sentinelpass-mobile-bridge/include (ADR-009); the static library
        // itself is NOT committed — populate SentinelPass/Native/libs with
        // build-ios.sh before linking.
        .systemLibrary(
            name: "sentinelpass",
            path: "SentinelPass/Native"
        ),
        // iOS App target
        .executableTarget(
            name: "SentinelPassApp",
            dependencies: ["sentinelpass"],
            path: "SentinelPass",
            exclude: ["Info.plist", "Native", "SentinelPass.entitlements"],
            sources: [
                "SentinelPassApp.swift",
                "ContentView.swift",
                "Models",
                "Services",
                "Views"
            ],
            resources: [
                .process("Assets.xcassets"),
            ],
            // The module map carries no `link` directive (per-SDK library
            // names differ), so SPM links the simulator static library here.
            // Library search path: SentinelPass/Native/libs (script-populated).
            linkerSettings: [
                .linkedLibrary("sentinelpass_mobile_bridge_ios_sim"),
            ]
        ),
        // Test target
        .testTarget(
            name: "SentinelPassTests",
            dependencies: ["SentinelPassApp"],
            path: "SentinelPassTests"
        ),
    ]
)
