import Foundation
import PackagePlugin

@main
struct ICNativeClientBindgenPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) async throws -> [Command] {
        let manifests = try findManifests(in: context.package.directory)
        guard manifests.count == 1, let manifest = manifests.first else {
            let paths = manifests.map(\.string).joined(separator: ", ")
            throw PluginError.invalidManifestCount(count: manifests.count, paths: paths)
        }

        let tool = try context.tool(named: "ic-candid-swift-bindgen")
        let outputDirectory = context.pluginWorkDirectory.appending("Generated")
        let output = outputDirectory.appending("ICNativeClientCandidBindings.swift")

        return [
            .prebuildCommand(
                displayName: "Generate Candid bindings for \(target.name)",
                executable: tool.path,
                arguments: [
                    "--manifest", manifest.string,
                    "--output", output.string,
                    "--project-root", context.package.directory.string,
                ],
                outputFilesDirectory: outputDirectory
            )
        ]
    }

    private func findManifests(in root: Path) throws -> [Path] {
        let rootURL = URL(fileURLWithPath: root.string, isDirectory: true)
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey]
        guard let enumerator = FileManager.default.enumerator(
            at: rootURL,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            throw PluginError.cannotReadPackage(root.string)
        }

        var results: [Path] = []
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: Set(keys))
            if values.isDirectory == true, [".build", ".swiftpm"].contains(url.lastPathComponent) {
                enumerator.skipDescendants()
                continue
            }
            guard values.isRegularFile == true,
                  url.lastPathComponent == "bindings.toml",
                  url.deletingLastPathComponent().lastPathComponent == "Candid" else {
                continue
            }
            results.append(Path(url.path))
        }
        return results.sorted { $0.string < $1.string }
    }
}
private enum PluginError: Error, CustomStringConvertible {
    case cannotReadPackage(String)
    case invalidManifestCount(count: Int, paths: String)

    var description: String {
        switch self {
        case .cannotReadPackage(let path):
            return "ICNativeClientBindgenPlugin cannot inspect package directory \(path)"
        case .invalidManifestCount(let count, let paths):
            let suffix = paths.isEmpty ? "" : ": \(paths)"
            return "ICNativeClientBindgenPlugin requires exactly one Candid/bindings.toml; found \(count)\(suffix)"
        }
    }
}
