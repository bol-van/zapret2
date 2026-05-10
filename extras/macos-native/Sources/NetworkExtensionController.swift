import Foundation
import NetworkExtension

enum TunnelControlResult {
    case ok(String)
    case unavailable(String)
    case failed(String)

    var message: String {
        switch self {
        case .ok(let message), .unavailable(let message), .failed(let message):
            return message
        }
    }

    var isOK: Bool {
        if case .ok = self {
            return true
        }
        return false
    }
}

final class NetworkExtensionController {
    private let localizedDescription = "Zapret2 Native Tunnel"
    private let providerBundleIdentifier: String?

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        let rawValue = environment["ZAPRET_TUNNEL_PROVIDER_BUNDLE_ID"] ?? ""
        providerBundleIdentifier = rawValue.isEmpty ? nil : rawValue
    }

    var isConfigured: Bool {
        providerBundleIdentifier != nil
    }

    func start(configFile: String, routeMode: String = "udp-development") -> TunnelControlResult {
        guard let providerBundleIdentifier else {
            return .unavailable("Network Extension provider bundle id is not configured")
        }

        switch loadOrCreateManager(providerBundleIdentifier: providerBundleIdentifier, configFile: configFile, routeMode: routeMode) {
        case .success(let manager):
            do {
                try save(manager)
                try load(manager)
                guard let session = manager.connection as? NETunnelProviderSession else {
                    return .failed("Network Extension session is not a tunnel provider session")
                }
                try session.startTunnel(options: ["configFile": configFile as NSString, "routeMode": routeMode as NSString])
                return .ok("Network Extension tunnel start requested")
            } catch {
                return .failed(error.localizedDescription)
            }
        case .failure(let error):
            return .failed(error.localizedDescription)
        }
    }

    func stop() -> TunnelControlResult {
        guard providerBundleIdentifier != nil else {
            return .unavailable("Network Extension provider bundle id is not configured")
        }
        switch loadManagers() {
        case .success(let managers):
            let matching = managers.filter { $0.localizedDescription == localizedDescription }
            matching.forEach { $0.connection.stopVPNTunnel() }
            return .ok(matching.isEmpty ? "Network Extension tunnel is not configured" : "Network Extension tunnel stop requested")
        case .failure(let error):
            return .failed(error.localizedDescription)
        }
    }

    func status() -> String {
        guard providerBundleIdentifier != nil else {
            return "Network Extension: provider bundle id not configured"
        }
        switch loadManagers() {
        case .success(let managers):
            guard let manager = managers.first(where: { $0.localizedDescription == localizedDescription }) else {
                return "Network Extension: tunnel profile not installed"
            }
            return "Network Extension: \(statusName(manager.connection.status))"
        case .failure(let error):
            return "Network Extension: \(error.localizedDescription)"
        }
    }

    private func loadOrCreateManager(providerBundleIdentifier: String, configFile: String, routeMode: String) -> Result<NETunnelProviderManager, Error> {
        switch loadManagers() {
        case .success(let managers):
            let manager = managers.first { $0.localizedDescription == localizedDescription } ?? NETunnelProviderManager()
            let providerProtocol = NETunnelProviderProtocol()
            providerProtocol.providerBundleIdentifier = providerBundleIdentifier
            providerProtocol.serverAddress = "zapret2-native"
            providerProtocol.providerConfiguration = ["configFile": configFile, "routeMode": routeMode]
            manager.localizedDescription = localizedDescription
            manager.protocolConfiguration = providerProtocol
            manager.isEnabled = true
            return .success(manager)
        case .failure(let error):
            return .failure(error)
        }
    }

    private func loadManagers() -> Result<[NETunnelProviderManager], Error> {
        var result: Result<[NETunnelProviderManager], Error>!
        let semaphore = DispatchSemaphore(value: 0)
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                result = .failure(error)
            } else {
                result = .success(managers ?? [])
            }
            semaphore.signal()
        }
        semaphore.wait()
        return result
    }

    private func save(_ manager: NETunnelProviderManager) throws {
        var result: Error?
        let semaphore = DispatchSemaphore(value: 0)
        manager.saveToPreferences { error in
            result = error
            semaphore.signal()
        }
        semaphore.wait()
        if let result {
            throw result
        }
    }

    private func load(_ manager: NETunnelProviderManager) throws {
        var result: Error?
        let semaphore = DispatchSemaphore(value: 0)
        manager.loadFromPreferences { error in
            result = error
            semaphore.signal()
        }
        semaphore.wait()
        if let result {
            throw result
        }
    }

    private func statusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid:
            return "invalid"
        case .disconnected:
            return "disconnected"
        case .connecting:
            return "connecting"
        case .connected:
            return "connected"
        case .reasserting:
            return "reasserting"
        case .disconnecting:
            return "disconnecting"
        @unknown default:
            return "unknown"
        }
    }
}
