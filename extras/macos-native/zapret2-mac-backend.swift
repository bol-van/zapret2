import Foundation

enum ExitCode: Int32 {
    case ok = 0
    case usage = 64
    case config = 78
    case unavailable = 69
}

let macbookVersion = "02.00.000"
let allowedProfileCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

func fileExists(_ path: String) -> Bool {
    FileManager.default.fileExists(atPath: path)
}

func executableDirectory() -> URL {
    URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.deletingLastPathComponent()
}

func zapretBase() -> URL {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_BASE"], !value.isEmpty {
        return URL(fileURLWithPath: value, isDirectory: true)
    }
    let current = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    if fileExists(current.appendingPathComponent("extras/macos-native/configs/base.args").path) {
        return current
    }
    let directory = executableDirectory()
    if directory.lastPathComponent == "build",
       directory.deletingLastPathComponent().lastPathComponent == "macos-native" {
        return directory.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }
    return directory.deletingLastPathComponent()
}

func repoPath(_ relativePath: String) -> String {
    let current = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
    let candidate = current.appendingPathComponent(relativePath).path
    if fileExists(candidate) {
        return candidate
    }
    return zapretBase().appendingPathComponent(relativePath).path
}

func executableExists(_ relativePath: String) -> Bool {
    let path = repoPath(relativePath)
    return FileManager.default.isExecutableFile(atPath: path)
}

func configDirectory() -> URL {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_CONFIG_DIR"], !value.isEmpty {
        return URL(fileURLWithPath: value, isDirectory: true)
    }
    return zapretBase().appendingPathComponent("extras/macos-native/configs", isDirectory: true)
}

func selectedProfileFile() -> URL {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_PROFILE_FILE"], !value.isEmpty {
        return URL(fileURLWithPath: value)
    }
    return zapretBase().appendingPathComponent("config/macos-native-profile")
}

func stateFile() -> URL {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_STATE_FILE"], !value.isEmpty {
        return URL(fileURLWithPath: value)
    }
    return zapretBase().appendingPathComponent("run/macos-native-state")
}

func bridgeCheckExecutable() -> String {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_BRIDGE_CHECK"], !value.isEmpty {
        return value
    }
    let installed = zapretBase().appendingPathComponent("bin/zapret2-core-bridge-check").path
    if FileManager.default.isExecutableFile(atPath: installed) {
        return installed
    }
    return zapretBase().appendingPathComponent("extras/macos-native/build/zapret2-core-bridge-check").path
}

func utunCheckExecutable() -> String {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_UTUN_CHECK"], !value.isEmpty {
        return value
    }
    let installed = zapretBase().appendingPathComponent("bin/zapret2-utun-check").path
    if FileManager.default.isExecutableFile(atPath: installed) {
        return installed
    }
    return zapretBase().appendingPathComponent("extras/macos-native/build/zapret2-utun-check").path
}

func utunRuntimeExecutable() -> String {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_NATIVE_UTUN_RUNTIME"], !value.isEmpty {
        return value
    }
    let installed = zapretBase().appendingPathComponent("bin/zapret2-utun-runtime").path
    if FileManager.default.isExecutableFile(atPath: installed) {
        return installed
    }
    return zapretBase().appendingPathComponent("extras/macos-native/build/zapret2-utun-runtime").path
}

func utunRuntimePidFile() -> URL {
    zapretBase().appendingPathComponent("run/macos-utun-runtime.pid")
}

func utunRuntimeStateFile() -> URL {
    zapretBase().appendingPathComponent("run/macos-utun-runtime-state")
}

func utunRuntimeLogFile() -> URL {
    zapretBase().appendingPathComponent("run/macos-utun-runtime.log")
}

func utunRuntimeRoutesFile() -> URL {
    zapretBase().appendingPathComponent("run/macos-utun-routes")
}

func backendMode() -> String {
    let value = ProcessInfo.processInfo.environment["ZAPRET_BACKEND_MODE"] ?? "utun"
    return value == "network-extension" ? "network-extension" : "utun"
}

func routeMode() -> String {
    let value = ProcessInfo.processInfo.environment["ZAPRET_TUNNEL_ROUTE_MODE"] ?? "udp-development"
    return value == "full-tunnel" ? "full-tunnel" : "udp-development"
}

func checkUtun() -> (ok: Bool, output: String) {
    let checker = utunCheckExecutable()
    guard FileManager.default.isExecutableFile(atPath: checker) else {
        return (false, "utun check is missing: \(checker)")
    }
    let result = runProcess(checker, [], currentDirectory: zapretBase())
    return (result.code == 0, result.output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func parseKeyValueLines(_ raw: String) -> [String: String] {
    var state: [String: String] = [:]
    for line in raw.split(whereSeparator: \.isNewline) {
        let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
        if parts.count == 2 {
            state[parts[0]] = parts[1]
        }
    }
    return state
}

func utunRuntimeState() -> [String: String] {
    guard let raw = try? String(contentsOf: utunRuntimeStateFile(), encoding: .utf8) else {
        return [:]
    }
    return parseKeyValueLines(raw)
}

func waitForUtunInterface(timeout: TimeInterval = 2.0) -> String? {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if let name = utunRuntimeState()["interface"], !name.isEmpty {
            return name
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
    return utunRuntimeState()["interface"]
}

func defaultEgressInterface() -> String? {
    if let value = ProcessInfo.processInfo.environment["ZAPRET_UTUN_EGRESS_IFACE"], !value.isEmpty {
        return value
    }
    let result = runProcess("/sbin/route", ["-n", "get", "default"])
    guard result.code == 0 else {
        return nil
    }
    for line in result.output.split(whereSeparator: \.isNewline) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("interface:") {
            let value = trimmed.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
    }
    return nil
}

func isUtunRuntimeRunning() -> Bool {
    if let raw = try? String(contentsOf: utunRuntimePidFile(), encoding: .utf8) {
        let pid = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if !pid.isEmpty, runProcess("/bin/kill", ["-0", pid]).code == 0 {
            return true
        }
    }

    let runtime = utunRuntimeExecutable()
    let result = runProcess("/usr/bin/pgrep", ["-f", "^\(runtime)"])
    return result.code == 0 && !result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
}

func startUtunRuntime() -> (ok: Bool, output: String) {
    let runtime = utunRuntimeExecutable()
    guard FileManager.default.isExecutableFile(atPath: runtime) else {
        return (false, "utun runtime is missing: \(runtime)")
    }
    if isUtunRuntimeRunning() {
        return (true, "utun runtime is already running")
    }

    do {
        try FileManager.default.createDirectory(at: utunRuntimePidFile().deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: utunRuntimeLogFile().path, contents: nil)
        let logHandle = try FileHandle(forWritingTo: utunRuntimeLogFile())
        logHandle.seekToEndOfFile()

        let process = Process()
        process.executableURL = URL(fileURLWithPath: runtime)
        var arguments = [
            "--pid-file", utunRuntimePidFile().path,
            "--state-file", utunRuntimeStateFile().path
        ]
        if let egress = defaultEgressInterface() {
            arguments += ["--egress-interface", egress]
        }
        process.arguments = arguments
        process.currentDirectoryURL = zapretBase()
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()
        logHandle.closeFile()

        Thread.sleep(forTimeInterval: 0.3)
        if isUtunRuntimeRunning() {
            return (true, "utun runtime started")
        }

        let log = (try? String(contentsOf: utunRuntimeLogFile(), encoding: .utf8)) ?? ""
        return (false, log.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "utun runtime exited during startup" : log.trimmingCharacters(in: .whitespacesAndNewlines))
    } catch {
        return (false, "could not start utun runtime: \(error.localizedDescription)")
    }
}

func isPublicIPv4(_ ip: String) -> Bool {
    let parts = ip.split(separator: ".").compactMap { UInt8($0) }
    guard parts.count == 4 else {
        return false
    }
    switch (parts[0], parts[1]) {
    case (0, _), (10, _), (127, _), (169, 254):
        return false
    case (172, 16...31), (192, 168):
        return false
    default:
        return true
    }
}

func publicIPv4Matches(in text: String) -> [String] {
    let pattern = #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#
    guard let regex = try? NSRegularExpression(pattern: pattern) else {
        return []
    }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    return regex.matches(in: text, range: range).compactMap { match in
        guard let range = Range(match.range, in: text) else {
            return nil
        }
        let ip = String(text[range])
        return isPublicIPv4(ip) ? ip : nil
    }
}

func isDiscordMediaIPv4(_ ip: String) -> Bool {
    ip.hasPrefix("104.29.") || ip.hasPrefix("162.159.")
}

func resolveIPv4(host: String) -> [String] {
    var ips = Set<String>()
    let dscache = runProcess("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", host])
    if dscache.code == 0 {
        publicIPv4Matches(in: dscache.output).forEach { ips.insert($0) }
    }
    let dig = runProcess("/usr/bin/dig", ["+short", "A", host])
    if dig.code == 0 {
        publicIPv4Matches(in: dig.output).forEach { ips.insert($0) }
    }
    return ips.sorted()
}

func homeForActiveUser() -> URL? {
    let user = ProcessInfo.processInfo.environment["SUDO_USER"].flatMap { $0 == "root" ? nil : $0 }
        ?? ProcessInfo.processInfo.environment["USER"].flatMap { $0 == "root" ? nil : $0 }
    guard let user else {
        return nil
    }
    let result = runProcess("/usr/bin/dscl", [".", "-read", "/Users/\(user)", "NFSHomeDirectory"])
    if result.code == 0, let home = result.output.split(whereSeparator: \.isNewline).first?.split(separator: " ").last {
        return URL(fileURLWithPath: String(home))
    }
    return URL(fileURLWithPath: "/Users/\(user)")
}

func discoverDiscordMediaIPsFromLogs() -> [String] {
    guard let home = homeForActiveUser() else {
        return []
    }
    let logs = home.appendingPathComponent("Library/Application Support/discord/logs")
    guard let files = try? FileManager.default.contentsOfDirectory(at: logs, includingPropertiesForKeys: [.contentModificationDateKey], options: [.skipsHiddenFiles]) else {
        return []
    }
    let sorted = files.sorted {
        let left = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        let right = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
        return left > right
    }
    var ips = Set<String>()
    for file in sorted.prefix(12) {
        let name = file.lastPathComponent.lowercased()
        guard name.contains("webrtc") || name.contains("renderer") else {
            continue
        }
        if let raw = try? String(contentsOf: file, encoding: .utf8) {
            raw.split(whereSeparator: \.isNewline)
                .map(String.init)
                .filter { line in
                    let lower = line.lowercased()
                    return lower.contains("discord") || lower.contains("rtc") || lower.contains("voice")
                }
                .flatMap(publicIPv4Matches)
                .filter(isDiscordMediaIPv4)
                .forEach { ips.insert($0) }
        }
    }
    return ips.sorted()
}

func discoverDiscordMediaIPs() -> [String] {
    var ips = Set<String>()
    if let configured = ProcessInfo.processInfo.environment["ZAPRET_DISCORD_MEDIA_IPS"], !configured.isEmpty {
        configured
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter(isPublicIPv4)
            .forEach { ips.insert($0) }
    }

    let latency = runProcess("/usr/bin/curl", ["-fsSL", "--connect-timeout", "5", "--max-time", "10", "https://latency.discord.media/rtc?v=2"])
    if latency.code == 0 {
        let pattern = #"\b(?:\d{1,3}\.){3}\d{1,3}(?=:\d+)"#
        if let regex = try? NSRegularExpression(pattern: pattern) {
            let range = NSRange(latency.output.startIndex..<latency.output.endIndex, in: latency.output)
            for match in regex.matches(in: latency.output, range: range) {
                if let range = Range(match.range, in: latency.output) {
                    let ip = String(latency.output[range])
                    if isPublicIPv4(ip) {
                        ips.insert(ip)
                    }
                }
            }
        }
    }

    for host in ["latency.discord.media", "discord.media"] {
        resolveIPv4(host: host).filter(isDiscordMediaIPv4).forEach { ips.insert($0) }
    }
    discoverDiscordMediaIPsFromLogs().forEach { ips.insert($0) }

    return ips.sorted()
}

func removeUtunRoutes() -> (ok: Bool, output: String) {
    guard let raw = try? String(contentsOf: utunRuntimeRoutesFile(), encoding: .utf8) else {
        return (true, "discord media routes: none")
    }
    var lines: [String] = []
    var ok = true
    for ip in raw.split(whereSeparator: \.isNewline).map(String.init).filter(isPublicIPv4) {
        let result = runProcess("/sbin/route", ["-n", "delete", "-host", ip])
        if result.code != 0 && !result.output.contains("not in table") {
            ok = false
        }
        lines.append("delete \(ip): \(result.code == 0 ? "ok" : result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
    }
    try? FileManager.default.removeItem(at: utunRuntimeRoutesFile())
    return (ok, lines.isEmpty ? "discord media routes: none" : lines.joined(separator: "\n"))
}

func installDiscordMediaRoutes(interface: String) -> (ok: Bool, output: String) {
    let ips = discoverDiscordMediaIPs()
    guard !ips.isEmpty else {
        return (false, "discord media route discovery returned no IPs")
    }

    _ = removeUtunRoutes()
    _ = runProcess("/sbin/ifconfig", [interface, "inet", "10.255.254.1", "10.255.254.2", "up"])
    _ = runProcess("/sbin/ifconfig", [interface, "mtu", "1500"])

    var installed: [String] = []
    var errors: [String] = []
    for ip in ips {
        let result = runProcess("/sbin/route", ["-n", "add", "-host", ip, "-interface", interface])
        if result.code == 0 || result.output.contains("File exists") {
            installed.append(ip)
        } else {
            errors.append("\(ip): \(result.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    do {
        try FileManager.default.createDirectory(at: utunRuntimeRoutesFile().deletingLastPathComponent(), withIntermediateDirectories: true)
        try (installed.joined(separator: "\n") + "\n").write(to: utunRuntimeRoutesFile(), atomically: true, encoding: .utf8)
    } catch {
        errors.append("could not save route state: \(error.localizedDescription)")
    }

    var output = "discord media routes installed: \(installed.count)"
    if !errors.isEmpty {
        output += "\nroute errors: \(errors.joined(separator: " | "))"
    }
    return (!installed.isEmpty, output)
}

func mediaRoutesEnabledByDefault() -> Bool {
    ProcessInfo.processInfo.environment["ZAPRET_ENABLE_DISCORD_MEDIA_ROUTES"] == "1"
}

func stopUtunRuntime() -> (ok: Bool, output: String) {
    let routeStop = removeUtunRoutes()
    guard let raw = try? String(contentsOf: utunRuntimePidFile(), encoding: .utf8) else {
        return (true, "\(routeStop.output)\nutun runtime is stopped")
    }
    let pid = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !pid.isEmpty else {
        return (true, "utun runtime is stopped")
    }

    _ = runProcess("/bin/kill", [pid])
    Thread.sleep(forTimeInterval: 0.5)
    if runProcess("/bin/kill", ["-0", pid]).code == 0 {
        _ = runProcess("/bin/kill", ["-9", pid])
    }
    try? FileManager.default.removeItem(at: utunRuntimePidFile())
    return (true, "\(routeStop.output)\nutun runtime is stopped")
}

func utunRuntimeDetail() -> String {
    guard let raw = try? String(contentsOf: utunRuntimeStateFile(), encoding: .utf8) else {
        return "utun runtime state: missing"
    }
    return raw.trimmingCharacters(in: .whitespacesAndNewlines)
}

func isValidProfileName(_ profile: String) -> Bool {
    !profile.isEmpty && profile.rangeOfCharacter(from: allowedProfileCharacters.inverted) == nil
}

func availableProfiles() -> [String] {
    let directory = configDirectory()
    guard let entries = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else {
        return []
    }
    return entries
        .filter { $0.pathExtension == "args" }
        .map { $0.deletingPathExtension().lastPathComponent }
        .filter(isValidProfileName)
        .sorted()
}

func selectedProfile() -> String {
    guard let raw = try? String(contentsOf: selectedProfileFile(), encoding: .utf8) else {
        return "base"
    }
    let profile = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return isValidProfileName(profile) ? profile : "base"
}

func profileConfigPath(_ profile: String) -> String {
    configDirectory().appendingPathComponent("\(profile).args").path
}

func runProcess(_ executable: String, _ arguments: [String], currentDirectory: URL? = nil) -> (code: Int32, output: String) {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe
    if let currentDirectory {
        process.currentDirectoryURL = currentDirectory
    }

    do {
        try process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    } catch {
        return (127, error.localizedDescription)
    }
}

func validateProfile(_ profile: String) -> (ok: Bool, output: String) {
    guard isValidProfileName(profile) else {
        return (false, "invalid profile name: \(profile)")
    }
    let path = profileConfigPath(profile)
    guard fileExists(path) else {
        return (false, "profile config is missing: \(path)")
    }
    let checker = bridgeCheckExecutable()
    guard FileManager.default.isExecutableFile(atPath: checker) else {
        return (false, "core bridge check is missing: \(checker)")
    }
    let result = runProcess(checker, [path], currentDirectory: zapretBase())
    return (result.code == 0, result.output.trimmingCharacters(in: .whitespacesAndNewlines))
}

func printProfiles() -> ExitCode {
    let selected = selectedProfile()
    for profile in availableProfiles() {
        print(profile == selected ? "* \(profile)" : "  \(profile)")
    }
    return .ok
}

func printProfile() -> ExitCode {
    let profile = selectedProfile()
    print("selected profile: \(profile)")
    print("config: \(profileConfigPath(profile))")
    return .ok
}

func checkProfile(_ profile: String) -> ExitCode {
    let result = validateProfile(profile)
    print(result.output)
    return result.ok ? .ok : .config
}

func setProfile(_ profile: String) -> ExitCode {
    let result = validateProfile(profile)
    guard result.ok else {
        print(result.output)
        return .config
    }
    do {
        try FileManager.default.createDirectory(at: selectedProfileFile().deletingLastPathComponent(), withIntermediateDirectories: true)
        try "\(profile)\n".write(to: selectedProfileFile(), atomically: true, encoding: .utf8)
        print("selected profile: \(profile)")
        print(result.output)
        return .ok
    } catch {
        print("could not save selected profile: \(error.localizedDescription)")
        return .config
    }
}

func timestamp() -> String {
    ISO8601DateFormatter().string(from: Date())
}

func readState() -> [String: String] {
    guard let raw = try? String(contentsOf: stateFile(), encoding: .utf8) else {
        return [:]
    }
    var state: [String: String] = [:]
    for line in raw.split(whereSeparator: \.isNewline) {
        let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
        if parts.count == 2 {
            state[parts[0]] = parts[1]
        }
    }
    return state
}

func writeState(_ values: [String: String]) throws {
    try FileManager.default.createDirectory(at: stateFile().deletingLastPathComponent(), withIntermediateDirectories: true)
    let body = values
        .sorted { $0.key < $1.key }
        .map { "\($0.key)=\($0.value)" }
        .joined(separator: "\n") + "\n"
    try body.write(to: stateFile(), atomically: true, encoding: .utf8)
}

func startBackend() -> ExitCode {
    let profile = selectedProfile()
    let validation = validateProfile(profile)
    guard validation.ok else {
        try? writeState([
            "desired": "stopped",
            "profile": profile,
            "tunnel": "not_started",
            "last_error": validation.output.replacingOccurrences(of: "\n", with: " | "),
            "updated_at": timestamp()
        ])
        print(validation.output)
        return .config
    }

    let mode = backendMode()
    let utun: (ok: Bool, output: String)
    if mode == "utun" {
        utun = checkUtun()
    } else {
        utun = (true, "utun check skipped")
    }
    guard utun.ok else {
        try? writeState([
            "backend_mode": mode,
            "desired": "stopped",
            "profile": profile,
            "profile_check": "ok",
            "tunnel": "utun_unavailable",
            "last_error": utun.output.replacingOccurrences(of: "\n", with: " | "),
            "updated_at": timestamp()
        ])
        print("native backend start failed")
        print("selected profile: \(profile)")
        print("backend mode: \(mode)")
        print(utun.output)
        return .unavailable
    }

    let configPath = profileConfigPath(profile)
    let launch: TunnelControlResult
    if mode == "network-extension" {
        launch = NetworkExtensionController().start(configFile: configPath, routeMode: routeMode())
    } else {
        let runtime = startUtunRuntime()
        if runtime.ok, mediaRoutesEnabledByDefault(), let interface = waitForUtunInterface() {
            let routes = installDiscordMediaRoutes(interface: interface)
            launch = routes.ok
                ? .ok("\(runtime.output); \(routes.output)")
                : .unavailable("\(runtime.output); \(routes.output)")
        } else if runtime.ok {
            launch = .ok("\(runtime.output); discord media routes deferred to avoid capturing Discord TCP during startup")
        } else {
            launch = runtime.ok
                ? .unavailable("\(runtime.output); utun interface did not appear in runtime state")
                : .unavailable(runtime.output)
        }
    }
    let tunnelState = launch.isOK ? (mode == "utun" ? "utun_runtime_running" : "starting") : (mode == "utun" ? "utun_runtime_failed" : "not_configured")
    try? writeState([
        "backend_mode": mode,
        "desired": launch.isOK ? "started" : "stopped",
        "profile": profile,
        "profile_check": "ok",
        "route_mode": routeMode(),
        "tunnel": tunnelState,
        "last_error": launch.isOK ? "" : launch.message,
        "updated_at": timestamp()
    ])
    print(launch.isOK ? "native backend start requested" : "native backend start unavailable")
    print("selected profile: \(profile)")
    print("backend mode: \(mode)")
    print("route mode: \(routeMode())")
    print(validation.output)
    if mode == "utun" {
        print(utun.output)
    }
    print(launch.message)
    return launch.isOK ? .ok : .unavailable
}

func stopBackend() -> ExitCode {
    let mode = backendMode()
    let stop: TunnelControlResult
    if mode == "network-extension" {
        stop = NetworkExtensionController().stop()
    } else {
        let runtime = stopUtunRuntime()
        stop = runtime.ok ? .ok(runtime.output) : .unavailable(runtime.output)
    }
    try? writeState([
        "backend_mode": mode,
        "desired": "stopped",
        "profile": selectedProfile(),
        "tunnel": "stopped",
        "last_error": stop.isOK ? "" : stop.message,
        "updated_at": timestamp()
    ])
    print(stop.message)
    print("native backend is stopped")
    return stop.isOK ? .ok : .unavailable
}

func statusBackend() -> ExitCode {
    let profile = selectedProfile()
    let state = readState()
    let validation = validateProfile(profile)
    let runtimeRunning = isUtunRuntimeRunning()
    print("native backend: \(runtimeRunning ? "running" : "not running")")
    print("MacBook version: \(macbookVersion)")
    print("selected profile: \(profile)")
    print("profile check: \(validation.ok ? "ok" : "failed")")
    print("backend mode: \(state["backend_mode"] ?? backendMode())")
    print("route mode: \(state["route_mode"] ?? routeMode())")
    print("desired state: \(state["desired"] ?? "stopped")")
    print("tunnel state: \(state["tunnel"] ?? "not_started")")
    if let updated = state["updated_at"] {
        print("state updated: \(updated)")
    }
    if let error = state["last_error"], !error.isEmpty {
        print("last error: \(error)")
    }
    print("engine init: presets load through bridge, Lua init and conntrack are available")
    let utun = checkUtun()
    print("utun check: \(utun.ok ? "ok" : "failed")")
    if !utun.output.isEmpty {
        print("utun detail: \(utun.output)")
    }
    print("utun runtime: \(runtimeRunning ? "running" : "stopped")")
    if runtimeRunning {
        print(utunRuntimeDetail().replacingOccurrences(of: "\n", with: " | "))
    }
    if let routes = try? String(contentsOf: utunRuntimeRoutesFile(), encoding: .utf8) {
        let routeList = routes.split(whereSeparator: \.isNewline).joined(separator: ", ")
        print("discord media routes: \(routeList.isEmpty ? "none" : routeList)")
    } else {
        print("discord media routes: none")
    }
    print("relay: IPv4 UDP relay available; active when utun runtime is running")
    if (state["backend_mode"] ?? backendMode()) == "network-extension" {
        print(NetworkExtensionController().status())
    } else {
        print("network extension: future signed mode")
    }
    return runtimeRunning ? .ok : .unavailable
}

func printUsage() {
    print("""
    Usage: zapret2-mac-backend <command>

    Commands:
      diagnose   Print native backend readiness
      profiles   List available native presets
      profile    Show selected native preset
      set-profile <name>
                 Validate and select native preset
      check-profile [name]
                 Validate selected or named native preset through the C bridge
      check-utun Validate that macOS allows opening an utun interface
      discover-discord-media
                 Resolve current Discord media UDP endpoints
      enable-discord-media-routes
                 Install narrow Discord media routes into the running utun interface
      disable-discord-media-routes
                 Remove Discord media routes
      start      Validate selected preset and request native backend start
      stop       Clear native backend requested state
      status     Show native backend status
    """)
}

func diagnose() -> ExitCode {
    print("Zapret2 native macOS backend")
    print("MacBook version: \(macbookVersion)")
    print("backend mode: \(backendMode())")
    print("packet boundary: utun/root active path, Network Extension prepared for future signing")
    print("production target: open-source utun/root runtime")
    print("zapret2 core API: nfq2/zapret2_engine.h")
    print("default blobs extraction: \(fileExists(repoPath("nfq2/zapret2_defaults.c")) ? "available" : "missing")")
    print("profile defaults extraction: \(fileExists(repoPath("nfq2/zapret2_profiles.c")) ? "available" : "missing")")
    print("argument-file loading: \(fileExists(repoPath("nfq2/zapret2_config.c")) ? "available" : "missing")")
    print("preset option parser: \(fileExists(repoPath("nfq2/zapret2_options.c")) ? "available" : "missing")")
    print("Darwin core binary: \(fileExists(repoPath("nfq2/dvtws2")) ? "built" : "missing")")
    print("Darwin core library: \(fileExists(repoPath("nfq2/libzapret2core-darwin.a")) ? "built" : "missing")")
    print("core bridge check: \(FileManager.default.isExecutableFile(atPath: bridgeCheckExecutable()) || executableExists("extras/macos-native/build/zapret2-core-bridge-check") ? "built" : "missing")")
    let utun = checkUtun()
    print("utun check: \(utun.ok ? "available" : "missing/blocked")")
    if !utun.output.isEmpty {
        print("utun detail: \(utun.output)")
    }
    print("local Lua dependency: \(fileExists(repoPath("extras/macos-native/.deps/lua-env.sh")) ? "available" : "missing")")
    print("selected profile: \(selectedProfile())")
    print("relay: IPv4 UDP relay available for narrow Discord media routes")
    let mediaIPs = discoverDiscordMediaIPs()
    print("discord media discovery: \(mediaIPs.isEmpty ? "no IPs found" : mediaIPs.joined(separator: ", "))")
    print("status: utun UDP relay ready for development testing")
    return .ok
}

@main
struct Zapret2MacBackendMain {
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let command = arguments.first

        switch command {
        case "diagnose":
            exit(diagnose().rawValue)
        case "profiles":
            exit(printProfiles().rawValue)
        case "profile":
            exit(printProfile().rawValue)
        case "set-profile":
            guard arguments.count >= 2 else {
                printUsage()
                exit(ExitCode.usage.rawValue)
            }
            exit(setProfile(arguments[1]).rawValue)
        case "check-profile":
            exit(checkProfile(arguments.count >= 2 ? arguments[1] : selectedProfile()).rawValue)
        case "check-utun":
            let result = checkUtun()
            print(result.output)
            exit(result.ok ? ExitCode.ok.rawValue : ExitCode.unavailable.rawValue)
        case "discover-discord-media":
            let ips = discoverDiscordMediaIPs()
            if ips.isEmpty {
                print("no Discord media IPs found")
                exit(ExitCode.unavailable.rawValue)
            }
            print(ips.joined(separator: "\n"))
            exit(ExitCode.ok.rawValue)
        case "enable-discord-media-routes":
            guard isUtunRuntimeRunning(), let interface = waitForUtunInterface() else {
                print("utun runtime is not running")
                exit(ExitCode.unavailable.rawValue)
            }
            let result = installDiscordMediaRoutes(interface: interface)
            print(result.output)
            exit(result.ok ? ExitCode.ok.rawValue : ExitCode.unavailable.rawValue)
        case "disable-discord-media-routes":
            let result = removeUtunRoutes()
            print(result.output)
            exit(result.ok ? ExitCode.ok.rawValue : ExitCode.unavailable.rawValue)
        case "status":
            exit(statusBackend().rawValue)
        case "start":
            exit(startBackend().rawValue)
        case "stop":
            exit(stopBackend().rawValue)
        case .some, .none:
            printUsage()
            exit(ExitCode.usage.rawValue)
        }
    }
}
