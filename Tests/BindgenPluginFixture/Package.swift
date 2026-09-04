// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "BindgenPluginFixture",
    platforms: [.macOS(.v13)],
    products: [.library(name: "Fixture", targets: ["Fixture"])],
    dependencies: [.package(path: "../..")],
    targets: [
        .target(
            name: "Fixture",
            dependencies: [.product(name: "ICNativeClient", package: "ICNativeClient")],
            plugins: [.plugin(name: "ICNativeClientBindgenPlugin", package: "ICNativeClient")]
        ),
        .testTarget(
            name: "FixtureTests",
            dependencies: [
                "Fixture",
                .product(name: "ICNativeClient", package: "ICNativeClient"),
            ]
        ),
    ]
)
