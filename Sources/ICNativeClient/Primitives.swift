// Low-level Internet Computer primitives: principal text/blob conversion,
// account identifiers, ICP amounts, request ids, and hashing helpers.

import CryptoKit
import Foundation

public enum ICPrincipal {
    private static let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    public static func parse(_ text: String) -> Data? {
        guard !text.isEmpty, text.utf8.count <= 63 else { return nil }
        let cleaned = text.lowercased().filter { $0 != "-" }
        guard !cleaned.isEmpty, cleaned.utf8.count <= 53 else { return nil }
        var buffer = 0
        var bits = 0
        var bytes = [UInt8]()
        for character in cleaned {
            guard let value = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                bytes.append(UInt8((buffer >> bits) & 0xff))
                buffer = bits == 0 ? 0 : buffer & ((1 << bits) - 1)
            }
        }
        guard bits == 0 || buffer & ((1 << bits) - 1) == 0 else { return nil }
        guard bytes.count >= 4 else { return nil }
        let checksum = Data(bytes.prefix(4))
        let blob = Data(bytes.dropFirst(4))
        guard blob.count <= 29,
              checksum == Data(ICCRC32.checksum(blob).bigEndianBytes) else {
            return nil
        }
        return blob
    }

    public static func selfAuthenticatingPublicKey(_ publicKey: Data) -> Data {
        ICSHA224.hash(publicKey) + Data([0x02])
    }

    public static func text(from blob: Data) -> String {
        let withChecksum = Data(ICCRC32.checksum(blob).bigEndianBytes) + blob
        var output = ""
        var buffer = 0
        var bits = 0
        for byte in withChecksum {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                output.append(alphabet[(buffer >> bits) & 0x1f])
            }
        }
        if bits > 0 {
            output.append(alphabet[(buffer << (5 - bits)) & 0x1f])
        }
        return stride(from: 0, to: output.count, by: 5)
            .map {
                let start = output.index(output.startIndex, offsetBy: $0)
                let length = min(5, output.distance(from: start, to: output.endIndex))
                let end = output.index(start, offsetBy: length)
                return String(output[start..<end])
            }
            .joined(separator: "-")
    }
}

public enum ICPAccountIdentifier {
    public static func defaultAccount(for principalText: String) throws -> Data {
        guard let principal = ICPrincipal.parse(principalText) else {
            throw ICClientError.invalidResponse("Invalid principal.")
        }
        return try account(for: principal, subaccount: Data(repeating: 0, count: 32))
    }

    public static func account(for principalText: String, subaccountPrincipal: String) throws -> Data {
        guard let principal = ICPrincipal.parse(principalText),
              let subaccountOwner = ICPrincipal.parse(subaccountPrincipal) else {
            throw ICClientError.invalidResponse("Invalid principal.")
        }
        var subaccount = Data(repeating: 0, count: 32)
        guard subaccountOwner.count < subaccount.count else {
            throw ICClientError.invalidResponse("Invalid subaccount principal.")
        }
        subaccount[0] = UInt8(subaccountOwner.count)
        subaccount.replaceSubrange(1..<(1 + subaccountOwner.count), with: subaccountOwner)
        return try account(for: principal, subaccount: subaccount)
    }

    public static func account(for principal: Data, subaccount: Data) throws -> Data {
        guard principal.count <= 29, subaccount.count == 32 else {
            throw ICClientError.invalidResponse("Principal must be at most 29 bytes and subaccount must be exactly 32 bytes.")
        }
        var payload = Data([0x0a])
        payload.append(Data("account-id".utf8))
        payload.append(principal)
        payload.append(subaccount)
        let hash = ICSHA224.hash(payload)
        return Data(ICCRC32.checksum(hash).bigEndianBytes) + hash
    }

    public static func parse(_ value: String) throws -> Data {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.count == 64, let account = Data(icHex: text), account.count == 32 {
            let checksum = Data(account.prefix(4))
            let hash = Data(account.dropFirst(4))
            guard checksum == Data(ICCRC32.checksum(hash).bigEndianBytes) else {
                throw ICClientError.invalidResponse("Invalid ICP account checksum.")
            }
            return account
        }
        return try defaultAccount(for: text)
    }
}

public enum ICPAmount {
    public static let feeE8s: UInt64 = 10_000

    public static func parse(_ text: String) -> UInt64? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count <= 2,
              !parts[0].isEmpty,
              parts[0].utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
              let whole = UInt64(parts[0]) else {
            return nil
        }
        let wholeProduct = whole.multipliedReportingOverflow(by: 100_000_000)
        if wholeProduct.overflow {
            return nil
        }
        let wholeE8s = wholeProduct.partialValue
        var fractionE8s: UInt64 = 0
        if parts.count == 2 {
            let fraction = parts[1]
            guard fraction.count <= 8,
                  fraction.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
            let padded = String(fraction) + String(repeating: "0", count: 8 - fraction.count)
            fractionE8s = UInt64(padded) ?? 0
        }
        let total = wholeE8s.addingReportingOverflow(fractionE8s)
        return total.overflow ? nil : total.partialValue
    }

    public static func format(_ e8s: UInt64, units: Bool = true) -> String {
        let whole = e8s / 100_000_000
        let fraction = e8s % 100_000_000
        let text: String
        if fraction == 0 {
            text = "\(whole)"
        } else {
            var fractionText = String(format: "%08llu", fraction)
            while fractionText.last == "0" {
                fractionText.removeLast()
            }
            text = "\(whole).\(fractionText)"
        }
        return units ? "\(text) ICP" : text
    }
}

public enum ICRequestID {
    public static func hash(of value: ICCBOR.Value) -> Data {
        switch value {
        case .text(let text):
            return sha256(Data(text.utf8))
        case .bytes(let bytes):
            return sha256(bytes)
        case .unsigned(let value):
            return sha256(ICRequestID.leb128(value))
        case .array(let values):
            return sha256(values.reduce(into: Data()) { $0.append(hash(of: $1)) })
        case .map(let values):
            let hashed = values.map { key, value in
                (hash(of: key), hash(of: value))
            }.sorted { $0.0.lexicographicallyPrecedes($1.0) }
            return sha256(hashed.reduce(into: Data()) {
                $0.append($1.0)
                $0.append($1.1)
            })
        case .tagged(_, let value):
            return hash(of: value)
        }
    }

    public static func leb128(_ value: UInt64) -> Data {
        var value = value
        var bytes = Data()
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 {
                byte |= 0x80
            }
            bytes.append(byte)
        } while value != 0
        return bytes
    }

    private static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

enum ICSHA224 {
    private static let constants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    static func hash(_ data: Data) -> Data {
        var message = data
        let bitLength = UInt64(message.count) * 8
        message.append(0x80)
        while message.count % 64 != 56 {
            message.append(0)
        }
        message.append(contentsOf: bitLength.bigEndianBytes)

        var h: [UInt32] = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
        for chunkStart in stride(from: 0, to: message.count, by: 64) {
            var words = Array(repeating: UInt32(0), count: 64)
            for index in 0..<16 {
                let offset = chunkStart + index * 4
                words[index] = UInt32(message[offset]) << 24
                words[index] |= UInt32(message[offset + 1]) << 16
                words[index] |= UInt32(message[offset + 2]) << 8
                words[index] |= UInt32(message[offset + 3])
            }
            for index in 16..<64 {
                let word15 = words[index - 15]
                let word2 = words[index - 2]
                let s0 = word15.rotatedRight(7) ^ word15.rotatedRight(18) ^ (word15 >> 3)
                let s1 = word2.rotatedRight(17) ^ word2.rotatedRight(19) ^ (word2 >> 10)
                words[index] = words[index - 16] &+ s0 &+ words[index - 7] &+ s1
            }

            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
            for index in 0..<64 {
                let s1 = e.rotatedRight(6) ^ e.rotatedRight(11) ^ e.rotatedRight(25)
                let ch = (e & f) ^ (~e & g)
                let temp1 = hh &+ s1 &+ ch &+ constants[index] &+ words[index]
                let s0 = a.rotatedRight(2) ^ a.rotatedRight(13) ^ a.rotatedRight(22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                hh = g
                g = f
                f = e
                e = d &+ temp1
                d = c
                c = b
                b = a
                a = temp1 &+ s0 &+ maj
            }
            h[0] = h[0] &+ a
            h[1] = h[1] &+ b
            h[2] = h[2] &+ c
            h[3] = h[3] &+ d
            h[4] = h[4] &+ e
            h[5] = h[5] &+ f
            h[6] = h[6] &+ g
            h[7] = h[7] &+ hh
        }

        return h.prefix(7).reduce(into: Data()) { $0.append(contentsOf: $1.bigEndianBytes) }
    }
}

enum ICCRC32 {
    static func checksum(_ data: Data) -> UInt32 {
        data.reduce(UInt32(0xffff_ffff)) { partial, byte in
            var crc = partial ^ UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) == 1 ? (crc >> 1) ^ 0xedb8_8320 : crc >> 1
            }
            return crc
        } ^ 0xffff_ffff
    }
}

extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: self.bigEndian) { Array($0) }
    }
}

extension Data {
    public init?(icHex: String) {
        let text = icHex.lowercased().filter { !$0.isWhitespace }
        guard text.count.isMultiple(of: 2) else { return nil }
        var bytes = Data()
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = bytes
    }

    public var icHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private extension UInt32 {
    func rotatedRight(_ amount: UInt32) -> UInt32 {
        (self >> amount) | (self << (32 - amount))
    }
}
