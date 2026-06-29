// swift-tools-version: 5.9
// Defines a local Swift Package so the native IC client can be reused by iOS apps
// without pulling application views, models, or backend-specific methods.

import PackageDescription

let package = Package(
    name: "ICNativeClient",
    platforms: [
        .iOS(.v17),
        .macOS(.v13),
    ],
    products: [
        .library(name: "ICNativeClient", targets: ["ICNativeClient"]),
    ],
    targets: [
        .target(name: "ICNativeClient"),
        .testTarget(name: "ICNativeClientTests", dependencies: ["ICNativeClient"]),
    ]
)
