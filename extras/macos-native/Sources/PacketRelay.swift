import Foundation
import Network
import NetworkExtension

struct RelayedPacket {
    let data: Data
    let networkProtocol: NSNumber
    let metadata: PacketMetadata?
}

struct PacketRelayResult {
    var udpPacketsSent = 0
    var unsupportedPackets = 0
    var malformedPackets = 0
}

protocol PacketRelaying {
    func relay(_ packets: [RelayedPacket], packetFlow: NEPacketTunnelFlow) throws -> PacketRelayResult
    func stop()
}

enum PacketRelayError: Error, CustomStringConvertible {
    case missingNetworkPath
    case unsupportedProtocol(String)
    case malformedPacket

    var description: String {
        switch self {
        case .missingNetworkPath:
            return "Network Extension packet relay is not implemented yet"
        case .unsupportedProtocol(let value):
            return "Network Extension relay does not support \(value) yet"
        case .malformedPacket:
            return "Network Extension relay received a malformed packet"
        }
    }
}

final class UdpPacketRelay: PacketRelaying {
    private let queue = DispatchQueue(label: "org.zapret2.native.udp-relay")
    private var sessions: [String: UdpRelaySession] = [:]

    func relay(_ packets: [RelayedPacket], packetFlow: NEPacketTunnelFlow) throws -> PacketRelayResult {
        var result = PacketRelayResult()

        for packet in packets {
            guard let metadata = packet.metadata else {
                result.malformedPackets += 1
                continue
            }
            guard metadata.transportProtocol == .udp else {
                result.unsupportedPackets += 1
                continue
            }
            guard let destinationPort = metadata.destination.port,
                  packet.data.count >= metadata.payloadOffset else {
                result.malformedPackets += 1
                continue
            }

            let payload = packet.data.subdata(in: metadata.payloadOffset..<packet.data.count)
            let key = sessionKey(metadata)
            let session = sessions[key] ?? makeSession(for: packet, metadata: metadata, packetFlow: packetFlow)
            sessions[key] = session
            session.updateTemplate(packet)
            session.send(payload)
            result.udpPacketsSent += 1
            _ = destinationPort
        }

        return result
    }

    func stop() {
        queue.sync {
            sessions.values.forEach { $0.cancel() }
            sessions.removeAll()
        }
    }

    private func makeSession(
        for packet: RelayedPacket,
        metadata: PacketMetadata,
        packetFlow: NEPacketTunnelFlow
    ) -> UdpRelaySession {
        let endpoint = NWEndpoint.Host(metadata.destination.address)
        let port = NWEndpoint.Port(rawValue: metadata.destination.port ?? 0) ?? .any
        let connection = NWConnection(host: endpoint, port: port, using: .udp)
        let session = UdpRelaySession(connection: connection, packetFlow: packetFlow, template: packet, queue: queue)
        session.start()
        return session
    }

    private func sessionKey(_ metadata: PacketMetadata) -> String {
        [
            metadata.ipVersion.rawValue,
            metadata.source.address,
            metadata.source.port.map(String.init) ?? "0",
            metadata.destination.address,
            metadata.destination.port.map(String.init) ?? "0"
        ].joined(separator: "|")
    }
}

private final class UdpRelaySession {
    private let connection: NWConnection
    private let packetFlow: NEPacketTunnelFlow
    private let queue: DispatchQueue
    private var template: RelayedPacket

    init(connection: NWConnection, packetFlow: NEPacketTunnelFlow, template: RelayedPacket, queue: DispatchQueue) {
        self.connection = connection
        self.packetFlow = packetFlow
        self.template = template
        self.queue = queue
    }

    func start() {
        connection.start(queue: queue)
        receive()
    }

    func updateTemplate(_ packet: RelayedPacket) {
        template = packet
    }

    func send(_ payload: Data) {
        connection.send(content: payload, completion: .contentProcessed { _ in })
    }

    func cancel() {
        connection.cancel()
    }

    private func receive() {
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self else { return }
            if let data, !data.isEmpty,
               let response = UdpResponsePacketBuilder.buildResponse(payload: data, template: self.template) {
                self.packetFlow.writePackets([response], withProtocols: [self.template.networkProtocol])
            }
            self.receive()
        }
    }
}

private enum UdpResponsePacketBuilder {
    static func buildResponse(payload: Data, template: RelayedPacket) -> Data? {
        guard let metadata = template.metadata else {
            return nil
        }
        switch metadata.ipVersion {
        case .ipv4:
            return buildIPv4Response(payload: payload, template: template, metadata: metadata)
        case .ipv6:
            return buildIPv6Response(payload: payload, template: template, metadata: metadata)
        }
    }

    private static func buildIPv4Response(payload: Data, template: RelayedPacket, metadata: PacketMetadata) -> Data? {
        var packet = [UInt8](template.data)
        guard metadata.ipHeaderLength >= 20,
              metadata.transportHeaderOffset == metadata.ipHeaderLength,
              packet.count >= metadata.payloadOffset else {
            return nil
        }

        let totalLength = metadata.ipHeaderLength + 8 + payload.count
        packet = Array(packet.prefix(metadata.payloadOffset))
        packet.append(contentsOf: payload)
        writeUInt16(UInt16(totalLength), to: &packet, at: 2)
        packet[8] = 64
        swapRanges(&packet, 12..<16, 16..<20)
        packet[10] = 0
        packet[11] = 0
        writeUInt16(ipv4HeaderChecksum(packet, headerLength: metadata.ipHeaderLength), to: &packet, at: 10)
        swapUdpPorts(&packet, at: metadata.transportHeaderOffset)
        writeUInt16(UInt16(8 + payload.count), to: &packet, at: metadata.transportHeaderOffset + 4)
        writeUInt16(0, to: &packet, at: metadata.transportHeaderOffset + 6)
        return Data(packet)
    }

    private static func buildIPv6Response(payload: Data, template: RelayedPacket, metadata: PacketMetadata) -> Data? {
        var packet = [UInt8](template.data)
        guard metadata.transportHeaderOffset == 40,
              packet.count >= metadata.payloadOffset else {
            return nil
        }

        packet = Array(packet.prefix(metadata.payloadOffset))
        packet.append(contentsOf: payload)
        writeUInt16(UInt16(8 + payload.count), to: &packet, at: 4)
        swapRanges(&packet, 8..<24, 24..<40)
        swapUdpPorts(&packet, at: metadata.transportHeaderOffset)
        writeUInt16(UInt16(8 + payload.count), to: &packet, at: metadata.transportHeaderOffset + 4)
        writeUInt16(0, to: &packet, at: metadata.transportHeaderOffset + 6)
        writeUInt16(udpIPv6Checksum(packet, udpOffset: metadata.transportHeaderOffset), to: &packet, at: metadata.transportHeaderOffset + 6)
        return Data(packet)
    }

    private static func swapUdpPorts(_ packet: inout [UInt8], at offset: Int) {
        let src0 = packet[offset]
        let src1 = packet[offset + 1]
        packet[offset] = packet[offset + 2]
        packet[offset + 1] = packet[offset + 3]
        packet[offset + 2] = src0
        packet[offset + 3] = src1
    }

    private static func swapRanges(_ packet: inout [UInt8], _ first: Range<Int>, _ second: Range<Int>) {
        let lhs = Array(packet[first])
        packet.replaceSubrange(first, with: packet[second])
        packet.replaceSubrange(second, with: lhs)
    }

    private static func writeUInt16(_ value: UInt16, to packet: inout [UInt8], at offset: Int) {
        packet[offset] = UInt8(value >> 8)
        packet[offset + 1] = UInt8(value & 0xff)
    }

    private static func ipv4HeaderChecksum(_ packet: [UInt8], headerLength: Int) -> UInt16 {
        finalizeChecksum(sumWords(packet[0..<headerLength]))
    }

    private static func udpIPv6Checksum(_ packet: [UInt8], udpOffset: Int) -> UInt16 {
        let udpLength = packet.count - udpOffset
        var sum: UInt32 = 0
        sum += sumWords(packet[8..<24])
        sum += sumWords(packet[24..<40])
        sum += UInt32(udpLength >> 16)
        sum += UInt32(udpLength & 0xffff)
        sum += UInt32(17)
        sum += sumWords(packet[udpOffset..<packet.count])
        let checksum = finalizeChecksum(sum)
        return checksum == 0 ? 0xffff : checksum
    }

    private static func sumWords(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        var sum: UInt32 = 0
        var index = bytes.startIndex
        while index < bytes.endIndex {
            let high = UInt16(bytes[index]) << 8
            let next = bytes.index(after: index)
            let low = next < bytes.endIndex ? UInt16(bytes[next]) : 0
            sum += UInt32(high | low)
            index = bytes.index(index, offsetBy: 2, limitedBy: bytes.endIndex) ?? bytes.endIndex
        }
        return sum
    }

    private static func finalizeChecksum(_ value: UInt32) -> UInt16 {
        var sum = value
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return ~UInt16(sum & 0xffff)
    }
}

final class UnimplementedPacketRelay: PacketRelaying {
    func relay(_ packets: [RelayedPacket], packetFlow: NEPacketTunnelFlow) throws -> PacketRelayResult {
        /*
         * A packet tunnel cannot become transparent by writing outbound packets
         * straight back into packetFlow. Production code must forward packets to
         * a real network path and inject only response packets back to macOS.
         */
        if !packets.isEmpty {
            throw PacketRelayError.missingNetworkPath
        }
        return PacketRelayResult()
    }

    func stop() {
    }
}
