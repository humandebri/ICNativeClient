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
        .plugin(name: "ICNativeClientBindgenPlugin", targets: ["ICNativeClientBindgenPlugin"]),
    ],
    targets: [
        .target(
            name: "CBlst",
            path: "Vendor/blst",
            sources: ["src/server.c", "build/assembly.S"],
            publicHeadersPath: "bindings",
            cSettings: [
                .headerSearchPath("src"),
                .define("__BLST_PORTABLE__", .when(platforms: [.iOS], configuration: .debug)),
            ]
        ),
        .target(name: "ICNativeClient", dependencies: ["CBlst"]),
        .binaryTarget(
            name: "ICNativeClientBindgenTool",
            path: "Artifacts/ICNativeClientBindgen.artifactbundle"
        ),
        .plugin(
            name: "ICNativeClientBindgenPlugin",
            capability: .buildTool(),
            dependencies: ["ICNativeClientBindgenTool"]
        ),
        .testTarget(
            name: "ICNativeClientTests",
            dependencies: ["ICNativeClient", "CBlst"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
