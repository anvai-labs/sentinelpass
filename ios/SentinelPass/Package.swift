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
        // Native C library target
        .systemLibrary(
            name: "sentinelpass_mobile_bridge",
            path: "SentinelPass/Native"
        ),
        // iOS App target
        .executableTarget(
            name: "SentinelPassApp",
            dependencies: ["sentinelpass_mobile_bridge"],
            path: "SentinelPass",
            exclude: ["Info.plist", "Native"],
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
            cSettings: [
                .headerSearchPath("Native/include"),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-LSentinelPass/Native/libs",
                    "-lsentinelpass_mobile_bridge_ios",
                ])
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
