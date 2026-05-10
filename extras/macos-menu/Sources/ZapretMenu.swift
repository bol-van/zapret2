import Cocoa
import UserNotifications

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSMenuItemValidation {
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let languageKey = "Zapret2MenuLanguage"
    private let startTimeKey = "Zapret2LastStartTime"
    private let stopTimeKey = "Zapret2LastStopTime"
    private let macbookVersion = "02.00.000"
    private var refreshTimer: Timer?
    private var restartingUntil: Date?
    private var busyStatusTitle: String?
    private var lockFileDescriptor: Int32 = -1

    private enum Language: String {
        case auto
        case ru
        case en
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        guard acquireSingleInstanceLock() else {
            NSApp.terminate(nil)
            return
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }

        if let button = statusItem.button {
            button.toolTip = "Zapret2"
        }

        rebuildMenu()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            self?.updateStatusIcon()
        }
    }

    private func rebuildMenu() {
        menu.removeAllItems()
        menu.delegate = self
        menu.autoenablesItems = true
        updateStatusIcon()
        let running = isZapretRunning()

        let header = NSMenuItem(title: currentStatusTitle(), action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        menu.addItem(.separator())

        let startItem = item(text("start"), #selector(startZapret))
        startItem.isEnabled = !running
        menu.addItem(startItem)

        let stopItem = item(text("stop"), #selector(stopZapret))
        stopItem.isEnabled = running
        menu.addItem(stopItem)

        let restartItem = item(text("restart"), #selector(restartZapret))
        restartItem.isEnabled = running
        menu.addItem(restartItem)
        menu.addItem(.separator())
        menu.addItem(profileMenuItem())
        menu.addItem(.separator())
        menu.addItem(item(text("updateHostlist"), #selector(updateHostlist)))
        menu.addItem(item(text("applyCurrentUpdate"), #selector(applyCurrentUpdate)))
        menu.addItem(item(text("fullUpdate"), #selector(fullUpdate)))
        menu.addItem(item(text("checkConnection"), #selector(checkConnection)))
        menu.addItem(item(text("showStatus"), #selector(showStatus)))
        menu.addItem(item(text("about"), #selector(showAbout)))
        menu.addItem(item(languageMenuTitle(), #selector(toggleLanguage)))
        menu.addItem(.separator())
        menu.addItem(item(text("quit"), #selector(quit)))

        statusItem.menu = menu
    }

    func menuWillOpen(_ menu: NSMenu) {
        rebuildMenu()
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        switch menuItem.action {
        case #selector(startZapret):
            return !isZapretRunning()
        case #selector(stopZapret):
            return isZapretRunning()
        case #selector(restartZapret):
            return isZapretRunning()
        default:
            return true
        }
    }

    private func updateStatusIcon() {
        if let button = statusItem.button {
            if let busyStatusTitle {
                button.title = "⏳"
                button.toolTip = busyStatusTitle
            } else if let until = restartingUntil, Date() < until {
                button.title = "🔀"
                button.toolTip = text("statusRestarting")
            } else {
                restartingUntil = nil
                button.title = isZapretRunning() ? "📳" : "📴"
                button.toolTip = currentStatusTitle()
            }
            button.image = nil
        }
    }

    private func statusImage(color: NSColor) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size)
        image.lockFocus()

        color.setFill()
        NSBezierPath(ovalIn: NSRect(x: 1, y: 1, width: 16, height: 16)).fill()

        NSColor.white.setFill()
        drawHand(in: NSRect(x: 3.6, y: 3.2, width: 10.8, height: 12.4))

        image.unlockFocus()
        image.isTemplate = false
        return image
    }

    private func drawHand(in rect: NSRect) {
        let palm = NSBezierPath(roundedRect: NSRect(x: rect.minX + 2.8, y: rect.minY, width: 5.4, height: 6.6), xRadius: 2.2, yRadius: 2.2)
        palm.fill()

        let fingerWidth: CGFloat = 1.8
        let gap: CGFloat = 0.45
        let baseX = rect.minX + 1.2
        let baseY = rect.minY + 5.1
        let heights: [CGFloat] = [5.8, 7.2, 6.6, 5.2]

        for index in 0..<4 {
            let x = baseX + CGFloat(index) * (fingerWidth + gap)
            let finger = NSBezierPath(roundedRect: NSRect(x: x, y: baseY, width: fingerWidth, height: heights[index]), xRadius: 0.9, yRadius: 0.9)
            finger.fill()
        }

        let thumb = NSBezierPath()
        thumb.move(to: NSPoint(x: rect.minX + 2.8, y: rect.minY + 4.3))
        thumb.line(to: NSPoint(x: rect.minX + 0.1, y: rect.minY + 5.6))
        thumb.line(to: NSPoint(x: rect.minX + 0.9, y: rect.minY + 7.3))
        thumb.line(to: NSPoint(x: rect.minX + 3.7, y: rect.minY + 5.7))
        thumb.close()
        thumb.fill()
    }

    private func item(_ title: String, _ action: Selector) -> NSMenuItem {
        let menuItem = NSMenuItem(title: title, action: action, keyEquivalent: "")
        menuItem.target = self
        return menuItem
    }

    private func profileMenuItem() -> NSMenuItem {
        let root = NSMenuItem(title: text("nativeProfileMenu"), action: nil, keyEquivalent: "")
        let submenu = NSMenu()
        let profiles = nativeProfiles()

        if profiles.isEmpty {
            let unavailable = NSMenuItem(title: text("statusUnavailable"), action: nil, keyEquivalent: "")
            unavailable.isEnabled = false
            submenu.addItem(unavailable)
        } else {
            for profile in profiles {
                let item = NSMenuItem(title: profile.name, action: #selector(selectProfile(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = profile.name
                item.state = profile.selected ? .on : .off
                submenu.addItem(item)
            }
        }

        root.submenu = submenu
        return root
    }

    private func currentStatusTitle() -> String {
        if let until = restartingUntil, Date() < until {
            return text("statusRestarting")
        }
        return isZapretRunning() ? text("statusRunning") : text("statusStopped")
    }

    private func isZapretRunning() -> Bool {
        let result = runShell("/usr/bin/pgrep -f '^/opt/zapret2/bin/zapret2-utun-runtime' >/dev/null && echo yes || echo no")
        return result.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func isInternetReachable() -> Bool {
        let output = runShell("""
        if /sbin/ping -q -c 1 -W 1000 1.1.1.1 >/dev/null 2>&1; then
          echo yes
        elif /usr/bin/curl -Is --connect-timeout 2 --max-time 3 https://www.apple.com >/dev/null 2>&1; then
          echo yes
        else
          echo no
        fi
        """)
        return output.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func isEndpointReachable(_ url: String) -> Bool {
        let escapedURL = shellEscape(url)
        let output = runShell("""
        if /usr/bin/curl -LIs --connect-timeout 3 --max-time 6 \(escapedURL) >/dev/null 2>&1; then
          echo yes
        else
          echo no
        fi
        """)
        return output.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func isTcpEndpointReachable(host: String, port: Int) -> Bool {
        let escapedHost = shellEscape(host)
        let output = runShell("""
        if /usr/bin/nc -G 3 -z \(escapedHost) \(port) >/dev/null 2>&1; then
          echo yes
        else
          echo no
        fi
        """)
        return output.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func isUdpEndpointProbeReachable(host: String, port: Int) -> Bool {
        let escapedHost = shellEscape(host)
        let output = runShell("""
        if /usr/bin/nc -u -G 3 -z \(escapedHost) \(port) >/dev/null 2>&1; then
          echo yes
        else
          echo no
        fi
        """)
        return output.trimmingCharacters(in: .whitespacesAndNewlines) == "yes"
    }

    private func nativeBackendTrafficStatus() -> (ready: Bool, detail: String) {
        let result = runSudo("/opt/zapret2/zapret2-menu-helper status")
        let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !output.isEmpty else {
            return (false, text("statusUnavailable"))
        }

        let notReadyMarkers = [
            "native backend: not running",
            "tunnel state: utun_unavailable",
            "tunnel state: utun_loop_pending",
            "utun packet loop pending",
            "packet relay loop is not implemented yet",
            "route setup and forwarding pending",
            "Network Extension UDP skeleton available",
            "Usage:"
        ]
        let ready = result.success && !notReadyMarkers.contains { output.contains($0) }
        return (ready, output)
    }

    private func isDiscordMediaReady(nativeBackendReady: Bool) -> Bool {
        guard nativeBackendReady else {
            return false
        }
        let profile = runSudo("/opt/zapret2/zapret2-menu-helper check-profile discord-media")
        guard profile.success else {
            return false
        }
        return isUdpEndpointProbeReachable(host: "stun.l.google.com", port: 19302)
    }

    private func setBusyStatus(_ message: String?) {
        busyStatusTitle = message
        updateStatusIcon()
    }

    @objc private func startZapret() {
        setBusyStatus(text("startingBackend"))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = self.runSudo("/opt/zapret2/zapret2-menu-helper start")
            DispatchQueue.main.async {
                self.setBusyStatus(nil)
                if result.success {
                    UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: self.startTimeKey)
                    self.showNotification(self.text("started"))
                } else {
                    self.showCommandError(result.output)
                }
                self.rebuildMenu()
            }
        }
    }

    @objc private func stopZapret() {
        setBusyStatus(text("stoppingBackend"))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = self.runSudo("/opt/zapret2/zapret2-menu-helper stop")
            DispatchQueue.main.async {
                self.setBusyStatus(nil)
                if result.success {
                    UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: self.stopTimeKey)
                    self.showNotification(self.text("stopped"))
                } else {
                    self.showCommandError(result.output)
                }
                self.rebuildMenu()
            }
        }
    }

    @objc private func restartZapret() {
        guard isZapretRunning() else {
            showDialog(text("restartUnavailable"), title: "Zapret2")
            rebuildMenu()
            return
        }
        guard isInternetReachable() else {
            showDialog(text("restartNoInternet"), title: "Zapret2")
            rebuildMenu()
            return
        }

        restartingUntil = Date().addingTimeInterval(3)
        updateStatusIcon()
        let result = runSudo("/opt/zapret2/zapret2-menu-helper restart")
        restartingUntil = Date().addingTimeInterval(3)
        if result.success {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: startTimeKey)
            showNotification(text("restarted"))
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func updateHostlist() {
        let before = hostlistLineCount()
        let result = runSudo("/opt/zapret2/zapret2-menu-helper update")
        let after = hostlistLineCount()
        let updatedAt = hostlistModifiedTime()
        let status = result.success ? text("hostlistUpdated") : text("hostlistUpdateFailed")
        let message = """
        \(status)

        \(text("before")) \(before)
        \(text("after")) \(after)
        \(text("lastListUpdate")) \(updatedAt)

        \(text("commandOutput"))
        \(result.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("noOutput") : result.output)
        """
        showDialog(message, title: "Zapret2")
        rebuildMenu()
    }

    @objc private func applyCurrentUpdate() {
        guard confirm(text("applyCurrentUpdateConfirm"), title: "Zapret2") else {
            rebuildMenu()
            return
        }

        setBusyStatus(text("applyingUpdate"))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let result = self.runSudo("/opt/zapret2/zapret2-menu-helper reinstall")
            DispatchQueue.main.async {
                self.setBusyStatus(nil)
                if result.success {
                    self.showNotification(self.text("applyCurrentUpdateFinished"))
                } else {
                    self.showCommandError(result.output)
                }
                self.rebuildMenu()
            }
        }
    }

    @objc private func fullUpdate() {
        guard confirm(text("fullUpdateConfirm"), title: "Zapret2") else {
            rebuildMenu()
            return
        }

        let result = runSudo("/opt/zapret2/zapret2-menu-helper update-all")
        if result.success {
            showNotification(text("fullUpdateFinished"))
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func checkConnection() {
        setBusyStatus(text("checkingConnection"))
        showNotification(text("checkingConnection"))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let backendTraffic = self.nativeBackendTrafficStatus()
            let internet = self.isInternetReachable()
            let apple = self.isEndpointReachable("https://www.apple.com")
            let youtube = self.isEndpointReachable("https://www.youtube.com")
            let discord = self.isEndpointReachable("https://discord.com/")
            let discordAuth = self.isEndpointReachable("https://discord.com/api/v9/experiments")
            let discordGateway = self.isTcpEndpointReachable(host: "gateway.discord.gg", port: 443)
            let discordMedia = self.isDiscordMediaReady(nativeBackendReady: backendTraffic.ready)
            let report = self.connectionReport(
                internet: internet,
                apple: apple,
                youtube: youtube,
                nativeBackendReady: backendTraffic.ready,
                discord: discord,
                discordAuth: discordAuth,
                discordGateway: discordGateway,
                discordMedia: discordMedia
            )
            DispatchQueue.main.async {
                self.setBusyStatus(nil)
                self.showDialog(report, title: "Zapret2")
                self.rebuildMenu()
            }
        }
    }

    @objc private func showStatus() {
        setBusyStatus(text("checkingStatus"))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let report = self.statusReport()
            DispatchQueue.main.async {
                self.setBusyStatus(nil)
                self.showDialog(report, title: "Zapret2")
                self.rebuildMenu()
            }
        }
    }

    @objc private func selectProfile(_ sender: NSMenuItem) {
        guard let profile = sender.representedObject as? String else {
            return
        }

        let result = runSudo("/opt/zapret2/zapret2-menu-helper set-profile \(shellEscape(profile))")
        if result.success {
            showNotification("\(text("profileChanged")) \(profile)")
        } else {
            showCommandError(result.output)
        }
        rebuildMenu()
    }

    @objc private func showAbout() {
        showDialog(aboutText(), title: "Zapret2")
        rebuildMenu()
    }

    @objc private func toggleLanguage() {
        let newLanguage: Language = effectiveLanguage() == .ru ? .en : .ru
        UserDefaults.standard.set(newLanguage.rawValue, forKey: languageKey)
        rebuildMenu()
        showNotification(text("languageChanged"))
    }

    @objc private func quit() {
        _ = runSudo("/opt/zapret2/zapret2-menu-helper stop")
        UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: stopTimeKey)

        let deadline = Date().addingTimeInterval(5)
        while isZapretRunning() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.25)
        }

        NSApp.terminate(nil)
    }

    private func runAdmin(_ command: String, success: String) {
        let output = runShell("/usr/bin/sudo -n \(command) 2>&1")
        if !output.contains("a password is required") && !output.contains("not in the sudoers") {
            showNotification(success)
        } else {
            showDialog(text("passwordlessSetupMissing"), title: text("errorTitle"))
        }

        rebuildMenu()
    }

    private func showNoInternetDialog() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = text("internetFailTitle")
        alert.informativeText = text("internetFailMessage")
        if isZapretRunning() {
            alert.addButton(withTitle: text("stop"))
        }
        alert.addButton(withTitle: text("close"))

        let response = alert.runModal()
        if response == .alertFirstButtonReturn, isZapretRunning() {
            stopZapret()
        }
    }

    private func runSudo(_ command: String) -> (success: Bool, output: String) {
        let output = runShell("/usr/bin/sudo -n \(command) 2>&1; echo __EXIT_CODE__:$?")
        let marker = "__EXIT_CODE__:"
        guard let range = output.range(of: marker, options: .backwards) else {
            return (false, output)
        }
        let codeText = output[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        let commandOutput = String(output[..<range.lowerBound])
        return (codeText == "0", commandOutput)
    }

    private func showCommandError(_ output: String) {
        if output.contains("a password is required") || output.contains("not in the sudoers") {
            showErrorDialog(text("passwordlessSetupMissing"))
        } else {
            showErrorDialog(output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("commandFailed") : output)
        }
    }

    private func runShell(_ command: String) -> String {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", command]
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return error.localizedDescription
        }
    }

    private func terminateOtherInstances() {
        // Kept for compatibility with existing installs; lock file is authoritative.
    }

    private func acquireSingleInstanceLock() -> Bool {
        let supportDirectory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Zapret2 Menu", isDirectory: true)
        try? FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
        let lockPath = supportDirectory.appendingPathComponent("Zapret2Menu.lock").path

        lockFileDescriptor = open(lockPath, O_CREAT | O_RDWR, 0o600)
        guard lockFileDescriptor >= 0 else {
            return false
        }

        if flock(lockFileDescriptor, LOCK_EX | LOCK_NB) == 0 {
            ftruncate(lockFileDescriptor, 0)
            let pid = "\(getpid())\n"
            _ = pid.withCString { write(lockFileDescriptor, $0, strlen($0)) }
            return true
        }

        close(lockFileDescriptor)
        lockFileDescriptor = -1
        return false
    }

    private func hostlistLineCount() -> String {
        runShell("/usr/bin/wc -l /opt/zapret2/ipset/zapret-hosts.txt 2>/dev/null | /usr/bin/awk '{print $1}'").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func userHostlistLineCount() -> String {
        runShell("/usr/bin/wc -l /opt/zapret2/ipset/zapret-hosts-user.txt 2>/dev/null | /usr/bin/awk '{print $1}'").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func hostlistModifiedTime() -> String {
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' /opt/zapret2/ipset/zapret-hosts.txt 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func hostlistModifiedDate() -> String {
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d' /opt/zapret2/ipset/zapret-hosts.txt 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func appModifiedDate() -> String {
        guard let executablePath = Bundle.main.executablePath else {
            return text("unknown")
        }
        let output = runShell("/usr/bin/stat -f '%Sm' -t '%Y-%m-%d' \(shellEscape(executablePath)) 2>/dev/null")
        return output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? text("unknown") : output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func zapretStartedAt() -> String {
        let output = runShell("""
        pid=$(/usr/bin/pgrep -f '^/opt/zapret2/bin/zapret2-utun-runtime' | /usr/bin/head -n 1)
        if [ -n "$pid" ]; then /bin/ps -o lstart= -p "$pid"; fi
        """).trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? text("unknown") : output
    }

    private func zapretRuntime() -> String {
        let output = runShell("""
        pid=$(/usr/bin/pgrep -f '^/opt/zapret2/bin/zapret2-utun-runtime' | /usr/bin/head -n 1)
        if [ -n "$pid" ]; then /bin/ps -o etimes= -p "$pid" | /usr/bin/xargs; fi
        """).trimmingCharacters(in: .whitespacesAndNewlines)
        if let seconds = TimeInterval(output) {
            return formatDuration(seconds)
        }
        return text("unknown")
    }

    private func timeSinceLastStop() -> String {
        let timestamp = UserDefaults.standard.double(forKey: stopTimeKey)
        if timestamp <= 0 {
            return text("never")
        }
        return formatDuration(Date().timeIntervalSince1970 - timestamp)
    }

    private func lastStopTime() -> String {
        let timestamp = UserDefaults.standard.double(forKey: stopTimeKey)
        if timestamp <= 0 {
            return text("never")
        }
        return formatDate(Date(timeIntervalSince1970: timestamp))
    }

    private func lastStartTime() -> String {
        let timestamp = UserDefaults.standard.double(forKey: startTimeKey)
        if timestamp <= 0 {
            return text("unknown")
        }
        return formatDate(Date(timeIntervalSince1970: timestamp))
    }

    private func nativeProfileStatus() -> String {
        let result = runSudo("/opt/zapret2/zapret2-menu-helper profile")
        if result.success {
            return result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return text("statusUnavailable")
    }

    private func nativeBackendStatus() -> String {
        let result = runSudo("/opt/zapret2/zapret2-menu-helper status")
        let output = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? text("statusUnavailable") : output
    }

    private func nativeProfiles() -> [(name: String, selected: Bool)] {
        let result = runSudo("/opt/zapret2/zapret2-menu-helper profiles")
        guard result.success else {
            return []
        }

        return result.output
            .split(whereSeparator: \.isNewline)
            .compactMap { line in
                let text = String(line)
                if text.hasPrefix("* ") {
                    return (String(text.dropFirst(2)), true)
                }
                if text.hasPrefix("  ") {
                    return (String(text.dropFirst(2)), false)
                }
                return nil
            }
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = effectiveLanguage() == .ru ? Locale(identifier: "ru_RU") : Locale(identifier: "en_US")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: date)
    }

    private func formatDateOnly(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = effectiveLanguage() == .ru ? Locale(identifier: "ru_RU") : Locale(identifier: "en_US")
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.string(from: date)
    }

    private func statusReport() -> String {
        let running = isZapretRunning()
        let restarting = restartingUntil.map { Date() < $0 } ?? false
        let statusLine = restarting ? text("humanRestarting") : (running ? text("humanRunning") : text("humanStopped"))
        let connectionLine = isInternetReachable() ? text("internetReachable") : text("internetUnreachable")
        let runtimeLine = running
            ? "\(text("runningSince")) \(zapretStartedAt())\n\(text("runningFor")) \(zapretRuntime())"
            : "\(text("lastStoppedAt")) \(lastStopTime())\n\(text("stoppedFor")) \(timeSinceLastStop())"

        let restartLine = running && isInternetReachable() ? text("restartAvailable") : text("restartBlocked")

        return """
        \(statusLine)
        \(connectionLine)

        \(runtimeLine)

        \(text("nativeProfileBlock"))
        \(nativeProfileStatus())

        \(text("nativeBackendBlock"))
        \(nativeBackendStatus())

        \(text("listsBlock"))
        \(text("lastListUpdate")) \(hostlistModifiedTime())
        \(text("mainListSize")) \(hostlistLineCount()) \(text("lines"))
        \(text("userListSize")) \(userHostlistLineCount()) \(text("lines"))

        \(text("startupBlock"))
        \(text("menuAutostart"))
        \(text("zapretNoAutostart"))

        \(text("actionsBlock"))
        \(restartLine)
        \(text("connectionCheckHint"))
        """
    }

    private func connectionReport(internet: Bool, apple: Bool, youtube: Bool, nativeBackendReady: Bool, discord: Bool, discordAuth: Bool, discordGateway: Bool, discordMedia: Bool) -> String {
        """
        \(text("connectionReportTitle"))
        \(text("internetStatus")) \(checkMark(internet))
        Apple: \(checkMark(apple))
        YouTube: \(checkMark(youtube))
        \(text("discordBypassBackend")) \(checkMark(nativeBackendReady))
        \(text("discordWeb")) \(checkMark(discord))
        \(text("discordAuthApi")) \(checkMark(discordAuth))
        \(text("discordGateway")) \(checkMark(discordGateway))
        \(text("discordVoiceMedia")) \(checkMark(discordMedia))
        \(text("discordVoiceMediaHint"))
        """
    }

    private func checkMark(_ value: Bool) -> String {
        value ? text("reachable") : text("unreachable")
    }

    private func aboutText() -> String {
        """
        \(text("aboutTitle"))

        \(text("aboutMacbookVersion")) \(macbookVersion)
        \(text("aboutDate")) \(formatDateOnly(Date()))
        \(text("aboutAppUpdated")) \(appModifiedDate())
        \(text("aboutListsUpdated")) \(hostlistModifiedDate())

        \(text("aboutWhat"))

        \(text("aboutHowToUse"))
        \(text("aboutStart"))
        \(text("aboutStop"))
        \(text("aboutRestart"))
        \(text("aboutConnection"))
        \(text("aboutUpdate"))
        \(text("aboutApplyUpdate"))
        \(text("aboutFullUpdate"))
        \(text("aboutQuit"))
        """
    }

    private func formatDuration(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        let days = total / 86400
        let hours = (total % 86400) / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if days > 0 {
            return "\(days)d \(hours)h \(minutes)m"
        }
        if hours > 0 {
            return "\(hours)h \(minutes)m"
        }
        if minutes > 0 {
            return "\(minutes)m \(secs)s"
        }
        return "\(secs)s"
    }

    private func shellEscape(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func showDialog(_ message: String, title: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func showErrorDialog(_ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = text("errorTitle")
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: text("copyErrorText"))

        if alert.runModal() == .alertSecondButtonReturn {
            copyToClipboard(message)
            showNotification(text("errorTextCopied"))
        }
    }

    private func copyToClipboard(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    private func confirm(_ message: String, title: String) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: text("continue"))
        alert.addButton(withTitle: text("cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    private func showNotification(_ message: String) {
        let content = UNMutableNotificationContent()
        content.title = "Zapret2"
        content.body = message
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private func selectedLanguage() -> Language {
        let rawValue = UserDefaults.standard.string(forKey: languageKey) ?? Language.auto.rawValue
        return Language(rawValue: rawValue) ?? .auto
    }

    private func effectiveLanguage() -> Language {
        let selected = selectedLanguage()
        if selected != .auto {
            return selected
        }

        let systemCode = Locale.preferredLanguages.first?.lowercased() ?? ""
        return systemCode.hasPrefix("ru") ? .ru : .en
    }

    private func languageMenuTitle() -> String {
        let current = effectiveLanguage() == .ru ? "Русский" : "English"
        let next = effectiveLanguage() == .ru ? "English" : "Русский"
        return "\(text("switchLanguage")): \(current) → \(next)"
    }

    private func text(_ key: String) -> String {
        let ru: [String: String] = [
            "start": "📳 Запустить",
            "stop": "📴 Остановить",
            "restart": "🔀 Перезапустить",
            "nativeProfileMenu": "🎛 Native профиль",
            "updateHostlist": "🔂 Обновить список",
            "applyCurrentUpdate": "♻️ Применить текущую версию",
            "fullUpdate": "⬇️ Обновить полностью",
            "checkConnection": "📶 Проверить соединение",
            "showStatus": "▶ Показать статус",
            "about": "ℹ️ О программе",
            "switchLanguage": "Переключить язык",
            "quit": "✖ Выключить программу",
            "statusRunning": "Статус: запущен",
            "statusStopped": "Статус: остановлен",
            "statusRestarting": "Статус: перезапускается",
            "started": "Zapret2 запущен",
            "stopped": "Zapret2 остановлен",
            "restarted": "Zapret2 перезапущен",
            "hostlistUpdated": "Список обновлён",
            "applyCurrentUpdateFinished": "Текущая версия применена. Программа будет перезапущена.",
            "fullUpdateFinished": "Полное обновление завершено. Программа будет перезапущена.",
            "applyCurrentUpdateConfirm": "Текущая сборка из рабочего репозитория будет пересобрана и установлена поверх текущей версии. Git обновление выполняться не будет.",
            "fullUpdateConfirm": "Будут загружены новые изменения из исходного репозитория, затем приложение и runtime будут переустановлены. После обновления меню Zapret2 перезапустится.",
            "restartUnavailable": "Перезапуск доступен только когда native zapret2 backend уже запущен. Сейчас соединение выключено.",
            "restartNoInternet": "Перезапуск заблокирован: интернет-соединение не проходит проверку.",
            "zapretRunningLine": "Zapret2: запущен",
            "zapretStoppedLine": "Zapret2: остановлен",
            "mainHostlist": "Основной список:",
            "userHostlist": "Пользовательский список:",
            "humanRunning": "📳 Zapret2 включён. Соединение сейчас должно работать через native zapret2 backend.",
            "humanStopped": "📴 Zapret2 выключен. Дополнительные правила обхода сейчас не применяются.",
            "humanRestarting": "🔀 Zapret2 перезапускается. Подождите несколько секунд, пока правила применятся заново.",
            "internetReachable": "📶 Интернет доступен: проверка соединения проходит.",
            "internetUnreachable": "📶 Интернет недоступен: проверка соединения не проходит.",
            "runningSince": "Запущен:",
            "runningFor": "Работает уже:",
            "lastStoppedAt": "Последняя остановка:",
            "stoppedFor": "Выключен уже:",
            "nativeProfileBlock": "Native профиль:",
            "nativeBackendBlock": "Native backend:",
            "listsBlock": "Списки обхода:",
            "mainListSize": "Основной список:",
            "userListSize": "Ваш ручной список:",
            "startupBlock": "Автозапуск:",
            "menuAutostart": "• меню Zapret2 запускается вместе с macOS",
            "zapretNoAutostart": "• сам native zapret2 backend после перезагрузки остаётся выключенным",
            "actionsBlock": "Действия:",
            "restartAvailable": "• 🔀 Перезапуск доступен, потому что native zapret2 backend включён",
            "restartBlocked": "• 🔀 Перезапуск заблокирован: native zapret2 backend выключен или нет интернет-соединения",
            "connectionCheckHint": "• 📶 Проверка соединения проверяет доступность интернета, а не включает zapret2",
            "startedAt": "Запущен:",
            "notRunning": "не запущен",
            "timeSinceLastStop": "Прошло с последней остановки:",
            "lastListUpdate": "Последнее обновление списка:",
            "lines": "строк",
            "unknown": "неизвестно",
            "never": "никогда",
            "before": "Было строк:",
            "after": "Стало строк:",
            "commandOutput": "Вывод команды:",
            "noOutput": "без вывода",
            "hostlistUpdateFailed": "Обновление списка завершилось с ошибкой",
            "statusUnavailable": "Статус недоступен",
            "commandFailed": "Команда не выполнена",
            "errorTitle": "Ошибка Zapret",
            "passwordlessSetupMissing": "Нет разрешения запускать zapret2 без пароля. Нужно один раз настроить правило sudoers.",
            "languageChanged": "Язык интерфейса переключён",
            "profileChanged": "Native профиль выбран:",
            "internetOk": "Интернет доступен.",
            "startingBackend": "Запускаю backend...",
            "stoppingBackend": "Останавливаю backend...",
            "checkingConnection": "Проверяю соединение...",
            "checkingStatus": "Проверяю статус...",
            "applyingUpdate": "Применяю обновление...",
            "connectionReportTitle": "Проверка соединения:",
            "internetStatus": "Интернет:",
            "reachable": "доступен",
            "unreachable": "недоступен",
            "internetFailTitle": "Интернет недоступен",
            "internetFailMessage": "Не удалось подключиться к проверочным адресам. Можно остановить zapret2 или закрыть окно и проверить Wi‑Fi/VPN/DNS вручную.",
            "aboutTitle": "Zapret2 Menu — управление native zapret2 backend из верхнего меню macOS.",
            "aboutMacbookVersion": "Версия для MacBook:",
            "aboutDate": "Текущая дата:",
            "aboutAppUpdated": "Последнее обновление программы:",
            "aboutListsUpdated": "Последнее обновление списков доступа:",
            "aboutWhat": "Приложение управляет локальным native zapret2 backend: запускает, останавливает, перезапускает сервис и показывает диагностику обхода.",
            "aboutHowToUse": "Как пользоваться:",
            "aboutStart": "• 📳 Запустить — включает native zapret2 backend.",
            "aboutStop": "• 📴 Остановить — выключает zapret2 и очищает правила.",
            "aboutRestart": "• 🔀 Перезапустить — доступно только когда zapret2 уже включён и интернет проходит проверку.",
            "aboutConnection": "• 📶 Проверить соединение — показывает статусы интернета, Apple, YouTube, Discord Web, Discord Gateway и готовность voice/media.",
            "aboutUpdate": "• 🔂 Обновить список — скачивает свежий список доменов обхода.",
            "aboutApplyUpdate": "• ♻️ Применить текущую версию — переустанавливает уже скачанную сборку без git обновления.",
            "aboutFullUpdate": "• ⬇️ Обновить полностью — подтягивает новые изменения программы, переустанавливает её и перезапускает меню.",
            "aboutQuit": "• ✖ Выключить программу — сначала останавливает zapret2, затем закрывает меню.",
            "close": "Закрыть",
            "continue": "Продолжить",
            "cancel": "Отмена",
            "copyErrorText": "Скопировать текст ошибки",
            "errorTextCopied": "Текст ошибки скопирован",
            "discordBypassBackend": "Discord bypass/backend:",
            "discordWeb": "Discord Web:",
            "discordAuthApi": "Discord Auth/API:",
            "discordGateway": "Discord Gateway:",
            "discordVoiceMedia": "Discord Voice/Media UDP:",
            "discordVoiceMediaHint": "Если bypass/backend недоступен, зелёные Discord Web/Auth/Gateway означают только прямую доступность endpoint, а не работающий обход приложения.",
            "nativeBackendRequired": "требуется native zapret2 backend"
        ]

        let en: [String: String] = [
            "start": "📳 Start",
            "stop": "📴 Stop",
            "restart": "🔀 Restart",
            "nativeProfileMenu": "🎛 Native Profile",
            "updateHostlist": "🔂 Update Hostlist",
            "applyCurrentUpdate": "♻️ Apply Current Version",
            "fullUpdate": "⬇️ Full Update",
            "checkConnection": "📶 Check Connection",
            "showStatus": "▶ Show Status",
            "about": "ℹ️ About",
            "switchLanguage": "Switch Language",
            "quit": "✖ Quit",
            "statusRunning": "Status: running",
            "statusStopped": "Status: stopped",
            "statusRestarting": "Status: restarting",
            "started": "Zapret2 started",
            "stopped": "Zapret2 stopped",
            "restarted": "Zapret2 restarted",
            "hostlistUpdated": "Hostlist updated",
            "applyCurrentUpdateFinished": "Current version applied. The app will restart.",
            "fullUpdateFinished": "Full update completed. The app will restart.",
            "applyCurrentUpdateConfirm": "The current build from this working repository will be rebuilt and installed over the current version. Git update will not run.",
            "fullUpdateConfirm": "New changes will be fetched from the upstream repository, then the app and runtime will be reinstalled. Zapret2 Menu will restart after the update.",
            "restartUnavailable": "Restart is only available when the native zapret2 backend is already running. The connection is currently off.",
            "restartNoInternet": "Restart is blocked: the internet connection check is failing.",
            "zapretRunningLine": "Zapret2: running",
            "zapretStoppedLine": "Zapret2: stopped",
            "mainHostlist": "Main hostlist:",
            "userHostlist": "User hostlist:",
            "humanRunning": "📳 Zapret2 is on. The connection should be using the native zapret2 backend.",
            "humanStopped": "📴 Zapret2 is off. Bypass rules are not applied right now.",
            "humanRestarting": "🔀 Zapret2 is restarting. Wait a few seconds while the rules are applied again.",
            "internetReachable": "📶 Internet is reachable: connection check passes.",
            "internetUnreachable": "📶 Internet is unreachable: connection check fails.",
            "runningSince": "Started:",
            "runningFor": "Running for:",
            "lastStoppedAt": "Last stopped:",
            "stoppedFor": "Stopped for:",
            "nativeProfileBlock": "Native profile:",
            "nativeBackendBlock": "Native backend:",
            "listsBlock": "Bypass lists:",
            "mainListSize": "Main list:",
            "userListSize": "Your manual list:",
            "startupBlock": "Startup:",
            "menuAutostart": "• Zapret2 Menu starts with macOS",
            "zapretNoAutostart": "• the native zapret2 backend stays off after reboot",
            "actionsBlock": "Actions:",
            "restartAvailable": "• 🔀 Restart is available because the native zapret2 backend is on",
            "restartBlocked": "• 🔀 Restart is blocked: zapret2 is off or internet is unavailable",
            "connectionCheckHint": "• 📶 Check Connection verifies internet reachability; it does not turn zapret2 on",
            "startedAt": "Started at:",
            "notRunning": "not running",
            "timeSinceLastStop": "Time since last stop:",
            "lastListUpdate": "Last hostlist update:",
            "lines": "lines",
            "unknown": "unknown",
            "never": "never",
            "before": "Before:",
            "after": "After:",
            "commandOutput": "Command output:",
            "noOutput": "no output",
            "hostlistUpdateFailed": "Hostlist update failed",
            "statusUnavailable": "Status unavailable",
            "commandFailed": "Command failed",
            "errorTitle": "Zapret2 Error",
            "passwordlessSetupMissing": "No permission to run zapret2 without a password. Configure the sudoers rule once.",
            "languageChanged": "Interface language switched",
            "profileChanged": "Native profile selected:",
            "internetOk": "Internet is available.",
            "startingBackend": "Starting backend...",
            "stoppingBackend": "Stopping backend...",
            "checkingConnection": "Checking connection...",
            "checkingStatus": "Checking status...",
            "applyingUpdate": "Applying update...",
            "connectionReportTitle": "Connection check:",
            "internetStatus": "Internet:",
            "reachable": "reachable",
            "unreachable": "unreachable",
            "internetFailTitle": "Internet unavailable",
            "internetFailMessage": "The test addresses are unreachable. You can stop zapret2 or close this window and check Wi-Fi/VPN/DNS manually.",
            "aboutTitle": "Zapret2 Menu — control the native zapret2 backend from the macOS menu bar.",
            "aboutMacbookVersion": "MacBook version:",
            "aboutDate": "Current date:",
            "aboutAppUpdated": "Last app update:",
            "aboutListsUpdated": "Last access list update:",
            "aboutWhat": "The app controls the local native zapret2 backend: start, stop, restart, and bypass diagnostics.",
            "aboutHowToUse": "How to use:",
            "aboutStart": "• 📳 Start — turns zapret2 on.",
            "aboutStop": "• 📴 Stop — turns zapret2 off and clears rules.",
            "aboutRestart": "• 🔀 Restart — available only when zapret2 is already on and the internet check passes.",
            "aboutConnection": "• 📶 Check Connection — shows internet, Apple, YouTube, Discord Web, Discord Gateway, and voice/media readiness.",
            "aboutUpdate": "• 🔂 Update Hostlist — downloads a fresh bypass domain list.",
            "aboutApplyUpdate": "• ♻️ Apply Current Version — reinstalls the already downloaded build without git update.",
            "aboutFullUpdate": "• ⬇️ Full Update — pulls new app changes, reinstalls the app, and restarts the menu.",
            "aboutQuit": "• ✖ Quit — stops zapret2 first, then closes the menu app.",
            "close": "Close",
            "continue": "Continue",
            "cancel": "Cancel",
            "copyErrorText": "Copy Error Text",
            "errorTextCopied": "Error text copied",
            "discordBypassBackend": "Discord bypass/backend:",
            "discordWeb": "Discord Web:",
            "discordAuthApi": "Discord Auth/API:",
            "discordGateway": "Discord Gateway:",
            "discordVoiceMedia": "Discord Voice/Media UDP:",
            "discordVoiceMediaHint": "If bypass/backend is unavailable, green Discord Web/Auth/Gateway checks only mean direct endpoint reachability, not working app traffic bypass.",
            "nativeBackendRequired": "native zapret2 backend required"
        ]

        let dictionary = effectiveLanguage() == .ru ? ru : en
        return dictionary[key] ?? key
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
