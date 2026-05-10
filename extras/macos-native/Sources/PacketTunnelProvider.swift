import Foundation
import NetworkExtension

@objc(PacketTunnelProvider)
public final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let processor = Zapret2CorePacketProcessor()
    private let relay: PacketRelaying = UdpPacketRelay()
    private let packetQueue = DispatchQueue(label: "org.zapret2.native.packet-loop")
    private let defaultConfigFile = "/opt/zapret2/extras/macos-native/configs/base.args"
    private var counters = PacketTunnelCounters()
    private enum RouteMode {
        case udpDevelopment
        case fullTunnel
    }

    public override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        do {
            let configFile = (options?["configFile"] as? NSString).map(String.init) ?? defaultConfigFile
            try processor.initialize(configFile: configFile)
        } catch {
            completionHandler(error)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = 1280
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.255.0.2"], subnetMasks: ["255.255.255.255"])
        settings.ipv6Settings = NEIPv6Settings(addresses: ["fd00:5a70:7265:7432::2"], networkPrefixLengths: [128])

        switch routeMode(options: options) {
        case .fullTunnel:
            settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
            settings.ipv6Settings?.includedRoutes = [NEIPv6Route.default()]
        case .udpDevelopment:
            settings.ipv4Settings?.includedRoutes = []
            settings.ipv6Settings?.includedRoutes = []
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }
            self?.readPackets()
            completionHandler(nil)
        }
    }

    public override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        relay.stop()
        completionHandler()
    }

    private func routeMode(options: [String: NSObject]?) -> RouteMode {
        let value = (options?["routeMode"] as? NSString).map(String.init) ?? "udp-development"
        return value == "full-tunnel" ? .fullTunnel : .udpDevelopment
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.packetQueue.async {
                self.handlePackets(packets, protocols: protocols)
                self.readPackets()
            }
        }
    }

    private func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        var outboundPackets: [RelayedPacket] = []

        for (index, packet) in packets.enumerated() {
            let proto = protocols[index]
            let metadata = PacketMetadataParser.parse(packet)
            counters.packetsRead += 1
            if metadata == nil {
                counters.packetsWithoutMetadata += 1
            }
            switch processor.process(packet: packet, inboundInterface: nil, outboundInterface: "utun") {
            case .pass(let data), .modify(let data):
                outboundPackets.append(RelayedPacket(data: data, networkProtocol: proto, metadata: metadata))
                counters.packetsRelayed += 1
            case .drop:
                counters.packetsDropped += 1
                continue
            case .error:
                outboundPackets.append(RelayedPacket(data: packet, networkProtocol: proto, metadata: metadata))
                counters.packetsRelayed += 1
            }
        }

        do {
            let result = try relay.relay(outboundPackets, packetFlow: packetFlow)
            counters.udpPacketsSent += result.udpPacketsSent
            counters.unsupportedPackets += result.unsupportedPackets
            counters.malformedPackets += result.malformedPackets
        } catch {
            cancelTunnelWithError(error)
        }
    }
}
