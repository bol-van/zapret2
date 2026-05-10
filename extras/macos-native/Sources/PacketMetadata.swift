import Foundation

enum IPVersion: String {
    case ipv4
    case ipv6
}

enum TransportProtocol: String {
    case tcp
    case udp
    case icmp
    case icmpv6
    case other
}

struct PacketEndpoint {
    let address: String
    let port: UInt16?
}

struct PacketMetadata {
    let ipVersion: IPVersion
    let transportProtocol: TransportProtocol
    let source: PacketEndpoint
    let destination: PacketEndpoint
    let ipHeaderLength: Int
    let transportHeaderOffset: Int
    let payloadOffset: Int
}

struct PacketTunnelCounters {
    var packetsRead = 0
    var packetsRelayed = 0
    var packetsDropped = 0
    var packetsWithoutMetadata = 0
    var udpPacketsSent = 0
    var unsupportedPackets = 0
    var malformedPackets = 0
}

enum PacketMetadataParser {
    static func parse(_ packet: Data) -> PacketMetadata? {
        packet.withUnsafeBytes { rawBuffer in
            guard let bytes = rawBuffer.bindMemory(to: UInt8.self).baseAddress, rawBuffer.count > 0 else {
                return nil
            }

            switch bytes[0] >> 4 {
            case 4:
                return parseIPv4(bytes: bytes, length: rawBuffer.count)
            case 6:
                return parseIPv6(bytes: bytes, length: rawBuffer.count)
            default:
                return nil
            }
        }
    }

    private static func parseIPv4(bytes: UnsafePointer<UInt8>, length: Int) -> PacketMetadata? {
        guard length >= 20 else {
            return nil
        }

        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20, length >= headerLength else {
            return nil
        }

        let protocolNumber = bytes[9]
        let sourceAddress = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        let destinationAddress = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
        let ports = parsePorts(bytes: bytes, length: length, offset: headerLength, protocolNumber: protocolNumber)

        return PacketMetadata(
            ipVersion: .ipv4,
            transportProtocol: transportProtocol(protocolNumber, ipv6: false),
            source: PacketEndpoint(address: sourceAddress, port: ports?.source),
            destination: PacketEndpoint(address: destinationAddress, port: ports?.destination),
            ipHeaderLength: headerLength,
            transportHeaderOffset: headerLength,
            payloadOffset: ports == nil ? headerLength : headerLength + 8
        )
    }

    private static func parseIPv6(bytes: UnsafePointer<UInt8>, length: Int) -> PacketMetadata? {
        guard length >= 40 else {
            return nil
        }

        var nextHeader = bytes[6]
        var transportOffset = 40
        skipIPv6ExtensionHeaders(bytes: bytes, length: length, nextHeader: &nextHeader, offset: &transportOffset)
        let ports = parsePorts(bytes: bytes, length: length, offset: transportOffset, protocolNumber: nextHeader)

        return PacketMetadata(
            ipVersion: .ipv6,
            transportProtocol: transportProtocol(nextHeader, ipv6: true),
            source: PacketEndpoint(address: formatIPv6(bytes: bytes + 8), port: ports?.source),
            destination: PacketEndpoint(address: formatIPv6(bytes: bytes + 24), port: ports?.destination),
            ipHeaderLength: 40,
            transportHeaderOffset: transportOffset,
            payloadOffset: ports == nil ? transportOffset : transportOffset + 8
        )
    }

    private static func skipIPv6ExtensionHeaders(
        bytes: UnsafePointer<UInt8>,
        length: Int,
        nextHeader: inout UInt8,
        offset: inout Int
    ) {
        while isSkippableIPv6ExtensionHeader(nextHeader), length >= offset + 2 {
            let currentHeader = nextHeader
            nextHeader = bytes[offset]

            if currentHeader == 44 {
                offset += 8
            } else {
                offset += (Int(bytes[offset + 1]) + 1) * 8
            }

            if offset >= length {
                break
            }
        }
    }

    private static func isSkippableIPv6ExtensionHeader(_ value: UInt8) -> Bool {
        switch value {
        case 0, 43, 44, 60:
            return true
        default:
            return false
        }
    }

    private static func parsePorts(
        bytes: UnsafePointer<UInt8>,
        length: Int,
        offset: Int,
        protocolNumber: UInt8
    ) -> (source: UInt16, destination: UInt16)? {
        guard protocolNumber == 6 || protocolNumber == 17, length >= offset + 4 else {
            return nil
        }
        return (readUInt16(bytes + offset), readUInt16(bytes + offset + 2))
    }

    private static func transportProtocol(_ protocolNumber: UInt8, ipv6: Bool) -> TransportProtocol {
        switch protocolNumber {
        case 6:
            return .tcp
        case 17:
            return .udp
        case 1:
            return .icmp
        case 58 where ipv6:
            return .icmpv6
        default:
            return .other
        }
    }

    private static func readUInt16(_ bytes: UnsafePointer<UInt8>) -> UInt16 {
        (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
    }

    private static func formatIPv6(bytes: UnsafePointer<UInt8>) -> String {
        var groups: [String] = []
        for index in stride(from: 0, to: 16, by: 2) {
            let value = readUInt16(bytes + index)
            groups.append(String(value, radix: 16))
        }
        return groups.joined(separator: ":")
    }
}
