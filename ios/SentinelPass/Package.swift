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
            // .linkedLibrary cannot express a SEARCH PATH — the library lives
            // in SentinelPass/Native/libs (script-populated, ADR-009: not
            // committed), so the -L/-l pair rides unsafeFlags. Relative -L
            // resolves against the package directory for both swift test and
            // xcodebuild SPM-scheme builds.
            linkerSettings: [
                .unsafeFlags([
                    "-LSentinelPass/Native/libs",
                    "-lsentinelpass_mobile_bridge_ios_sim",
                ])
            ]
        ),
        // Test target (WBS-828): real bridge-contract XCTests over the C
        // ABI, executed on an iOS simulator via
        // xcodebuild test -scheme SentinelPass-Package (CI: ios.yml).
        .testTarget(
            name: "SentinelPassTests",
            dependencies: ["sentinelpass"],
            path: "SentinelPassTests",
            linkerSettings: [
                .unsafeFlags([
                    "-LSentinelPass/Native/libs",
                    "-lsentinelpass_mobile_bridge_ios_sim",
                ])
            ]
        ),
    ]
)
