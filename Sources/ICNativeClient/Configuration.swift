// Network and identity-provider configuration used by the reusable IC client.
// App-specific bundles can build this value from Info.plist or runtime settings.

import Foundation

public enum ICClientAPIVersion: String, Sendable {
    case v2
    case v3
    case v4
}

public struct ICClientConfiguration: Equatable, Sendable {
    public let canisterId: String
    public let apiBaseURL: URL
    public let identityProvider: URL
    public let derivationOrigin: String

    public init(
        canisterId: String,
        apiBaseURL: URL = URL(string: "https://ic0.app")!,
        identityProvider: URL = URL(string: "https://id.ai/#authorize")!,
        derivationOrigin: String
    ) {
        self.canisterId = canisterId
        self.apiBaseURL = apiBaseURL
        self.identityProvider = identityProvider
        self.derivationOrigin = derivationOrigin
    }

    public func apiURL(
        for requestType: String,
        canisterId requestCanisterId: String? = nil,
        version: ICClientAPIVersion? = nil
    ) -> URL {
        let version = version ?? defaultAPIVersion(for: requestType)
        let base = apiBaseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return URL(string: "\(base)/api/\(version.rawValue)/canister/\(requestCanisterId ?? canisterId)/\(requestType)")!
    }

    private func defaultAPIVersion(for requestType: String) -> ICClientAPIVersion {
        switch requestType {
        case "query", "read_state":
            return .v3
        case "call":
            return .v4
        default:
            return .v2
        }
    }
}
