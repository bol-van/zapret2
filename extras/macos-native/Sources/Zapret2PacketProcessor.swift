import Foundation

enum Zapret2PacketVerdict {
    case pass(Data)
    case modify(Data)
    case drop
    case error(String)
}

protocol Zapret2PacketProcessing {
    func process(packet: Data, inboundInterface: String?, outboundInterface: String?) -> Zapret2PacketVerdict
}

final class Zapret2CorePacketProcessor: Zapret2PacketProcessing {
    private let bridge = Zapret2CoreBridge()

    func initialize(configFile: String) throws {
        try bridge.initialize(configFile: configFile)
    }

    func process(packet: Data, inboundInterface: String?, outboundInterface: String?) -> Zapret2PacketVerdict {
        bridge.process(packet: packet, inboundInterface: inboundInterface, outboundInterface: outboundInterface)
    }
}

final class PassthroughPacketProcessor: Zapret2PacketProcessing {
    func process(packet: Data, inboundInterface: String?, outboundInterface: String?) -> Zapret2PacketVerdict {
        .pass(packet)
    }
}
