import Foundation

public enum ICClientAPIVersion: String, Sendable {
    case v2
    case v3
    case v4
}

/// The certificate root used to turn untrusted replica responses into verified data.
public enum ICTrustRoot: Equatable, Sendable {
    case mainnet
    case custom(Data)

    public var derEncodedPublicKey: Data {
        switch self {
        case .mainnet: Self.mainnetDERKey
        case .custom(let key): key
        }
    }

    // The 133-byte key embedded by the official agent-rs implementation.
    private static let mainnetDERKey = Data([
        0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06,
        0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61,
        0x00, 0x81, 0x4c, 0x0e, 0x6e, 0xc7, 0x1f, 0xab, 0x58, 0x3b, 0x08, 0xbd,
        0x81, 0x37, 0x3c, 0x25, 0x5c, 0x3c, 0x37, 0x1b, 0x2e, 0x84, 0x86, 0x3c,
        0x98, 0xa4, 0xf1, 0xe0, 0x8b, 0x74, 0x23, 0x5d, 0x14, 0xfb, 0x5d, 0x9c,
        0x0c, 0xd5, 0x46, 0xd9, 0x68, 0x5f, 0x91, 0x3a, 0x0c, 0x0b, 0x2c, 0xc5,
        0x34, 0x15, 0x83, 0xbf, 0x4b, 0x43, 0x92, 0xe4, 0x67, 0xdb, 0x96, 0xd6,
        0x5b, 0x9b, 0xb4, 0xcb, 0x71, 0x71, 0x12, 0xf8, 0x47, 0x2e, 0x0d, 0x5a,
        0x4d, 0x14, 0x50, 0x5f, 0xfd, 0x74, 0x84, 0xb0, 0x12, 0x91, 0x09, 0x1c,
        0x5f, 0x87, 0xb9, 0x88, 0x83, 0x46, 0x3f, 0x98, 0x09, 0x1a, 0x0b, 0xaa,
        0xae,
    ])
}

public struct ICNetworkConfiguration: Equatable, Sendable {
    public static let defaultRequestTimeout: TimeInterval = 20
    public static let defaultPollingInterval: Duration = .seconds(1)
    public static let defaultMaximumPollingAttempts = 30
    public static let `default` = ICNetworkConfiguration(
        validatedRequestTimeout: defaultRequestTimeout,
        pollingInterval: defaultPollingInterval,
        maximumPollingAttempts: defaultMaximumPollingAttempts
    )

    public let requestTimeout: TimeInterval
    public let pollingInterval: Duration
    public let maximumPollingAttempts: Int

    public init(
        requestTimeout: TimeInterval = Self.defaultRequestTimeout,
        pollingInterval: Duration = Self.defaultPollingInterval,
        maximumPollingAttempts: Int = Self.defaultMaximumPollingAttempts
    ) throws {
        guard requestTimeout.isFinite, requestTimeout > 0 else {
            throw ICClientError.invalidConfiguration("HTTP request timeout must be finite and greater than zero.")
        }
        guard pollingInterval > .zero else {
            throw ICClientError.invalidConfiguration("Polling interval must be greater than zero.")
        }
        guard maximumPollingAttempts > 0 else {
            throw ICClientError.invalidConfiguration("Maximum polling attempts must be greater than zero.")
        }
        self.init(
            validatedRequestTimeout: requestTimeout,
            pollingInterval: pollingInterval,
            maximumPollingAttempts: maximumPollingAttempts
        )
    }

    private init(
        validatedRequestTimeout: TimeInterval,
        pollingInterval: Duration,
        maximumPollingAttempts: Int
    ) {
        requestTimeout = validatedRequestTimeout
        self.pollingInterval = pollingInterval
        self.maximumPollingAttempts = maximumPollingAttempts
    }
}

public struct ICAuthenticationOptions: Equatable, Sendable {
    public static let maximumTargets = 1_000
    public static let `default` = ICAuthenticationOptions(
        validatedMaxTimeToLiveNanoseconds: nil,
        canonicalTargets: nil
    )

    public let maxTimeToLiveNanoseconds: UInt64?
    public let targets: [String]?

    public init(
        maxTimeToLiveNanoseconds: UInt64? = nil,
        targets: [String]? = nil
    ) throws {
        if let maxTimeToLiveNanoseconds {
            guard maxTimeToLiveNanoseconds > 0,
                  maxTimeToLiveNanoseconds <= ICClientConfiguration.maximumDelegationTTLNanoseconds else {
                throw ICClientError.invalidConfiguration("Internet Identity delegation lifetime must not exceed 30 days.")
            }
        }

        let canonicalTargets: [String]?
        if let targets {
            guard !targets.isEmpty, targets.count <= Self.maximumTargets else {
                throw ICClientError.invalidConfiguration("Authentication targets must contain between 1 and 1000 canister IDs.")
            }
            let parsed = try targets.map { target -> String in
                guard let principal = ICPrincipal.parse(target) else {
                    throw ICClientError.invalidConfiguration("Authentication target is not a valid principal: \(target)")
                }
                return ICPrincipal.text(from: principal)
            }
            guard Set(parsed).count == parsed.count else {
                throw ICClientError.invalidConfiguration("Authentication targets must not contain duplicates.")
            }
            canonicalTargets = parsed
        } else {
            canonicalTargets = nil
        }
        self.init(
            validatedMaxTimeToLiveNanoseconds: maxTimeToLiveNanoseconds,
            canonicalTargets: canonicalTargets
        )
    }

    private init(
        validatedMaxTimeToLiveNanoseconds: UInt64?,
        canonicalTargets: [String]?
    ) {
        maxTimeToLiveNanoseconds = validatedMaxTimeToLiveNanoseconds
        targets = canonicalTargets
    }
}

public struct ICClientConfiguration: Equatable, Sendable {
    public static let defaultDelegationTTLNanoseconds: UInt64 = 28_800_000_000_000
    public static let maximumDelegationTTLNanoseconds: UInt64 = 2_592_000_000_000_000
    public static let defaultMaximumResponseBytes = 10 * 1_024 * 1_024

    public let canisterId: String
    public let apiBaseURL: URL
    public let internetIdentityURL: URL
    public let derivationOrigin: String
    public let trustRoot: ICTrustRoot
    public let delegationTTLNanoseconds: UInt64
    public let maximumResponseBytes: Int
    public let network: ICNetworkConfiguration

    public init(
        canisterId: String,
        apiBaseURL: URL? = nil,
        internetIdentityURL: URL? = nil,
        derivationOrigin: String,
        trustRoot: ICTrustRoot = .mainnet,
        delegationTTLNanoseconds: UInt64 = Self.defaultDelegationTTLNanoseconds,
        maximumResponseBytes: Int = Self.defaultMaximumResponseBytes,
        network: ICNetworkConfiguration = .default
    ) throws {
        guard ICPrincipal.parse(canisterId) != nil else { throw ICClientError.invalidCanisterId }
        guard let resolvedAPIBaseURL = apiBaseURL ?? URL(string: "https://ic0.app"),
              let resolvedInternetIdentityURL = internetIdentityURL ?? URL(string: "https://id.ai/authorize") else {
            throw ICClientError.invalidConfiguration("Default URLs could not be constructed.")
        }
        try Self.validateHTTPSURL(resolvedAPIBaseURL, name: "IC API base URL", allowsQuery: false, requiredPath: nil)
        try ICRC167Codec.validateInternetIdentityURL(resolvedInternetIdentityURL)
        try Self.validateOrigin(derivationOrigin)
        guard delegationTTLNanoseconds > 0,
              delegationTTLNanoseconds <= Self.maximumDelegationTTLNanoseconds else {
            throw ICClientError.invalidConfiguration("Delegation lifetime must be between 1 ns and 30 days.")
        }
        guard maximumResponseBytes > 0 else {
            throw ICClientError.invalidConfiguration("Maximum response size must be greater than zero.")
        }
        try ICCertificateVerifier.validateRootKey(trustRoot.derEncodedPublicKey)
        self.canisterId = canisterId
        self.apiBaseURL = resolvedAPIBaseURL
        self.internetIdentityURL = resolvedInternetIdentityURL
        self.derivationOrigin = derivationOrigin
        self.trustRoot = trustRoot
        self.delegationTTLNanoseconds = delegationTTLNanoseconds
        self.maximumResponseBytes = maximumResponseBytes
        self.network = network
    }

    public func apiURL(
        for requestType: String,
        canisterId requestCanisterId: String? = nil,
        version: ICClientAPIVersion? = nil
    ) throws -> URL {
        guard ["query", "call", "read_state"].contains(requestType),
              let canister = ICPrincipal.parse(requestCanisterId ?? canisterId) else {
            throw ICClientError.invalidConfiguration("Invalid IC API request path.")
        }
        let selectedVersion = version ?? defaultAPIVersion(for: requestType)
        var components = URLComponents(url: apiBaseURL, resolvingAgainstBaseURL: false)
        let basePath = components?.percentEncodedPath.trimmingCharacters(in: CharacterSet(charactersIn: "/")) ?? ""
        let prefix = basePath.isEmpty ? "" : "/\(basePath)"
        components?.percentEncodedPath = "\(prefix)/api/\(selectedVersion.rawValue)/canister/\(ICPrincipal.text(from: canister))/\(requestType)"
        guard let url = components?.url else {
            throw ICClientError.invalidConfiguration("IC API URL could not be constructed.")
        }
        return url
    }

    private func defaultAPIVersion(for requestType: String) -> ICClientAPIVersion {
        switch requestType {
        case "query", "read_state": .v3
        case "call": .v4
        default: .v2
        }
    }

    static func validateHTTPSURL(
        _ url: URL,
        name: String,
        allowsQuery: Bool,
        requiredPath: String?
    ) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.percentEncodedFragment == nil,
              allowsQuery || components.percentEncodedQuery == nil,
              requiredPath == nil || components.percentEncodedPath == requiredPath else {
            throw ICClientError.invalidConfiguration("\(name) must be an HTTPS URL without credentials or a fragment.")
        }
    }

    private static func validateOrigin(_ origin: String) throws {
        guard let url = URL(string: origin),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/",
              components.percentEncodedQuery == nil,
              components.percentEncodedFragment == nil else {
            throw ICClientError.invalidConfiguration("Derivation origin must be an HTTPS origin without a path, query, fragment, or credentials.")
        }
    }
}
