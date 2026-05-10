import Foundation

private struct Zapret2MacPacketResultC {
    var verdict: Int32
    var packetLen: Int
}

@_silgen_name("zapret2_mac_core_init")
private func zapret2_mac_core_init(_ configFile: UnsafePointer<CChar>?, _ errbuf: UnsafeMutablePointer<CChar>?, _ errbufLen: Int) -> Int32

@_silgen_name("zapret2_mac_core_process_packet")
private func zapret2_mac_core_process_packet(
    _ packet: UnsafePointer<UInt8>?,
    _ packetLen: Int,
    _ ifin: UnsafePointer<CChar>?,
    _ ifout: UnsafePointer<CChar>?,
    _ outPacket: UnsafeMutablePointer<UInt8>?,
    _ outPacketCapacity: Int
) -> Zapret2MacPacketResultC

@_silgen_name("zapret2_mac_core_shutdown")
private func zapret2_mac_core_shutdown()

enum Zapret2CoreBridgeError: Error, CustomStringConvertible {
    case initFailed(String)

    var description: String {
        switch self {
        case .initFailed(let message):
            return message
        }
    }
}

final class Zapret2CoreBridge {
    private(set) var isReady = false

    func initialize(configFile: String) throws {
        var errbuf = [CChar](repeating: 0, count: 512)
        let rc = configFile.withCString { configPtr in
            zapret2_mac_core_init(configPtr, &errbuf, errbuf.count)
        }
        if rc == 0 {
            isReady = true
            return
        }
        let message = String(cString: errbuf)
        throw Zapret2CoreBridgeError.initFailed(message.isEmpty ? "zapret2 core init failed" : message)
    }

    func process(packet: Data, inboundInterface: String?, outboundInterface: String?) -> Zapret2PacketVerdict {
        guard isReady else {
            return .error("zapret2 core bridge is not initialized")
        }

        var output = [UInt8](repeating: 0, count: max(packet.count + 1500, 65536))
        let result = packet.withUnsafeBytes { packetBytes in
            inboundInterface.withOptionalCString { ifinPtr in
                outboundInterface.withOptionalCString { ifoutPtr in
                    zapret2_mac_core_process_packet(
                        packetBytes.bindMemory(to: UInt8.self).baseAddress,
                        packet.count,
                        ifinPtr,
                        ifoutPtr,
                        &output,
                        output.count
                    )
                }
            }
        }

        switch result.verdict {
        case 0:
            return .pass(Data(output.prefix(result.packetLen)))
        case 1:
            return .modify(Data(output.prefix(result.packetLen)))
        case 2:
            return .drop
        default:
            return .error("zapret2 core packet processing failed")
        }
    }

    deinit {
        if isReady {
            zapret2_mac_core_shutdown()
        }
    }
}

private extension Optional where Wrapped == String {
    func withOptionalCString<Result>(_ body: (UnsafePointer<CChar>?) -> Result) -> Result {
        switch self {
        case .some(let value):
            return value.withCString(body)
        case .none:
            return body(nil)
        }
    }
}
