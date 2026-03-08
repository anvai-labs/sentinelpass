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
        // iOS App target
        .executableTarget(
            name: "SentinelPassApp",
            dependencies: [],
            path: "SentinelPass",
            exclude: ["Info.plist"],
            sources: [
                "SentinelPassApp.swift",
                "ContentView.swift",
                "Models",
                "Services",
                "Views"
            ],
            resources: [
                .process("Assets.xcassets"),
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
