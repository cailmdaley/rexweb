import AppKit
import CommonCrypto
import SQLite3
import CoreGraphics
import Network
import Security
import WebKit

struct Config {
  var top: Double?, left: Double?, right: Double?, bottom: Double?
  var gap: Double?, header: Double?, radius: Double?
  var port = 18802
  var searchURL = "https://www.google.com/search?q=%s"
  var fallbackBrowser = ""
  var linkTarget = "split"
  var rexBin = ""
  var configError: String?

  static let dir = ProcessInfo.processInfo.environment["REXWEB_DIR"].map { URL(fileURLWithPath: $0) }
    ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".rexweb")

  static func findRex() -> String {
    let fm = FileManager.default
    let home = fm.homeDirectoryForCurrentUser.path
    var candidates: [String] = []
    for root in ["/Applications", "\(home)/Applications"] {
      for app in ["Rex", "Rex Beta"] {
        candidates.append("\(root)/\(app).app/Contents/Helpers/Rex Server.rex/Contents/MacOS/rex")
      }
    }
    candidates += ["/opt/homebrew/bin/rex", "/usr/local/bin/rex", "\(home)/.local/bin/rex"]
    return candidates.first { fm.isExecutableFile(atPath: $0) } ?? "rex"
  }

  static func load() -> Config {
    var c = Config()
    defer {
      if let bin = ProcessInfo.processInfo.environment["REX_BIN"], !bin.isEmpty { c.rexBin = bin }
      if c.rexBin.isEmpty { c.rexBin = findRex() }
    }
    let url = dir.appendingPathComponent("config.json")
    guard let data = try? Data(contentsOf: url) else { return c }
    guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      c.configError = "~/.rexweb/config.json isn't a valid JSON object"
      return c
    }
    func n(_ k: String) -> Double? { (o[k] as? NSNumber)?.doubleValue }
    c.top = n("top"); c.left = n("left"); c.right = n("right"); c.bottom = n("bottom")
    c.gap = n("gap"); c.header = n("header"); c.radius = n("radius")
    if let p = o["port"] as? NSNumber { c.port = p.intValue }
    if let b = o["rex_bin"] as? String { c.rexBin = b }
    if let u = o["search_url"] as? String {
      if u.contains("%s") { c.searchURL = u } else { c.configError = "search_url needs %s where the query goes" }
    }
    if let f = o["fallback_browser"] as? String { c.fallbackBrowser = f }
    if let t = o["links"] as? String {
      if ["tab", "split"].contains(t) { c.linkTarget = t } else { c.configError = "links must be \"split\" or \"tab\"" }
    }
    return c
  }
}

var config = Config.load()

enum Auth {
  static let file = Config.dir.appendingPathComponent("token")

  static let token: String = {
    let fm = FileManager.default
    try? fm.createDirectory(at: Config.dir, withIntermediateDirectories: true)
    if let t = try? String(contentsOf: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines), t.count >= 32 {
      try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
      return t
    }
    var bytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    let t = bytes.map { String(format: "%02x", $0) }.joined()
    fm.createFile(atPath: file.path, contents: Data(t.utf8), attributes: [.posixPermissions: 0o600])
    return t
  }()

  static func matches(_ given: String?) -> Bool {
    guard let given else { return false }
    let a = Array(given.utf8), b = Array(token.utf8)
    guard a.count == b.count else { return false }
    return zip(a, b).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
  }
}

struct Insets: Equatable {
  var top, left, right, bottom, gap, header, radius: Double
  var floatHeader = 36.0
  var floatTop = 38.0, floatLeft = 0.0, floatRight = 0.0
}

enum RexChrome {
  static let domain = "com.superlogical.rex" as CFString

  static func value(_ key: String) -> Any? {
    CFPreferencesCopyAppValue("Workspace.\(key)" as CFString, domain)
  }

  static func read() -> Insets {
    CFPreferencesAppSynchronize(domain)
    let compact = value("paneDensity") as? String == "compact"
    let e = compact ? 0.0 : 8.0
    var i = compact
      ? Insets(top: 41, left: e, right: e, bottom: e, gap: 2, header: 35, radius: 0)
      : Insets(top: 46, left: e, right: e, bottom: e, gap: 8, header: 36, radius: 10)
    let headers = value("paneHeaderVisibility") as? String
      ?? (((value("showsPaneHeaders") as? NSNumber)?.boolValue ?? true) ? "always" : "never")
    if headers != "always" { i.header = 0; i.floatHeader = 0 }
    let toolbar = value("toolbarBehavior") as? String ?? "alwaysShow"
    i.floatTop = i.top - e
    if value("tabStyle") as? String != "vertical", toolbar != "alwaysShow" { i.top = e; i.floatTop = 0 }
    if value("tabStyle") as? String == "vertical" {
      i.top = e
      i.floatTop = 38
      let collapsed = (value("sidebarCollapsed") as? NSNumber)?.boolValue ?? false
      if !collapsed {
        let w = (value("sidebarWidth") as? NSNumber)?.doubleValue ?? 0
        if value("sidebarPosition") as? String == "right" { i.right = w; i.floatRight = w } else { i.left = w; i.floatLeft = w; i.floatTop = 0 }
      }
    }
    if let t = config.top { i.top = t }
    if let l = config.left { i.left = l }
    if let r = config.right { i.right = r }
    if let b = config.bottom { i.bottom = b }
    if let g = config.gap { i.gap = g }
    if let h = config.header { i.header = h }
    if let r = config.radius { i.radius = r }
    return i
  }
}

func orNull(_ v: Any?) -> Any { v ?? NSNull() }

func log(_ s: String) {
  FileHandle.standardError.write(("[rexweb] " + s + "\n").data(using: .utf8)!)
}

enum Rex {
  static let queue = DispatchQueue(label: "rexweb.rex", attributes: .concurrent)

  /// A rex process for `args`, sent to `host` (a server address) or, when nil, to the local server.
  static func process(_ args: [String], host: String? = nil) -> Process {
    let p = Process()
    let full = (host.map { ["-S", $0] } ?? []) + args
    if config.rexBin.contains("/") {
      p.executableURL = URL(fileURLWithPath: config.rexBin)
      p.arguments = full
    } else {
      p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      p.arguments = [config.rexBin] + full
    }
    return p
  }

  @discardableResult
  static func run(_ args: [String], host: String? = nil) -> Data? {
    let p = process(args, host: host)
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { log("rex failed: \(error)"); return nil }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return p.terminationStatus == 0 ? data : nil
  }

  static func json(_ o: Any) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: o), as: UTF8.self) }

  static func view(_ session: String, host: String?) -> [String: Any]? {
    guard let data = run(["api", "call", "session.view", json(["session_id": session])], host: host) else { return nil }
    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
  }

  static func async(_ args: [String], host: String? = nil) { queue.async { run(args, host: host) } }

  /// The server's hosts, as the address of each one's first endpoint.
  static func hosts() -> [String]? {
    guard let data = run(["api", "call", "hosts.list", "{}"]),
          let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    return (o["hosts"] as? [[String: Any]] ?? []).compactMap { ($0["endpoints"] as? [String])?.first }
  }

  /// A pane that `rexweb-remote hold` keeps sets its terminal title to "rexweb URL". Any program can set a title, so
  /// a pane counts only if its block label, which only rex calls can set, also starts with "rexweb".
  struct Mark { let session, block, url: String }

  /// The URL in a marked title: an http or https address, or empty for a blank page.
  static func mark(title: String) -> String? {
    guard title.hasPrefix("rexweb ") else { return nil }
    let url = String(title.dropFirst(7))
    guard url.isEmpty || ["http", "https"].contains(URL(string: url)?.scheme?.lowercased()) else { return nil }
    return url
  }

  static func labelled(_ m: Mark, host: String?) -> Bool {
    guard let data = run(["api", "call", "session.list_blocks", json(["session_id": m.session])], host: host),
          let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
    let b = (o["blocks"] as? [[String: Any]] ?? []).first { $0["block_id"] as? String == m.block }
    return (b?["label"] as? String)?.hasPrefix("rexweb") == true
  }

  static let scanScript = """
  local out = {}
  for _, s in ipairs(rex.call("session.list").sessions or {}) do
    rex.session.attach{ session_id = s.session_id }
    for _, b in ipairs((rex.call("session.list_blocks", { session_id = s.session_id }) or {}).blocks or {}) do
      if b.creator_name == "com.superlogical.terminal" and (b.label or ""):sub(1, 6) == "rexweb" then
        local t = (rex.call("block.method", { session_id = s.session_id, block_id = b.block_id, method = "title" }) or {}).title or ""
        if t:sub(1, 7) == "rexweb " then out[#out + 1] = { session = s.session_id, block = b.block_id, title = t } end
      end
    end
  end
  return out
  """

  /// Every marked, labelled pane on `host`, found in one rex process.
  static func scan(host: String?) -> [Mark] {
    guard let data = run(["do", "-e", scanScript, "--json"], host: host),
          let list = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
    return list.compactMap { m in
      guard let s = m["session"] as? String, let b = m["block"] as? String,
            let url = mark(title: m["title"] as? String ?? "") else { return nil }
      return Mark(session: s, block: b, url: url)
    }
  }

  /// Read one line of `rex events --json`: the session whose layout it may change, and the mark if it is a marked
  /// pane's title change. `cli` collects the CLI clients that have joined, as every rex call RexWeb makes does; any
  /// other client connecting to a session or leaving it, such as the Rex app, can change which of its panes show.
  static func event(_ line: Data, cli: inout Set<String>) -> (session: String?, mark: Mark?) {
    guard let o = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { return (nil, nil) }
    let p = o["payload"] as? [String: Any] ?? [:]
    switch o["type"] as? String {
    case "client_joined":
      let c = p["client"] as? [String: Any]
      if (c?["info"] as? [String: Any])?["kind"] as? String == "cli", let id = c?["client_id"] as? String { cli.insert(id) }
    case "client_left":
      if let id = p["client_id"] as? String { cli.remove(id) }
    case "session_destroyed":
      return (p["session_id"] as? String, nil)
    case "session_event":
      guard let s = p["session_id"] as? String, let e = p["event"] as? [String: Any] else { break }
      let ep = e["payload"] as? [String: Any] ?? [:]
      switch e["type"] as? String {
      case "session_view_changed", "active_window_changed", "block_closed", "window_closed":
        return (s, nil)
      case "client_connected", "client_disconnected":
        if !cli.contains(ep["client_id"] as? String ?? "") { return (s, nil) }
      case "block_event":
        if ep["name"] as? String == "title_changed", let b = ep["block_id"] as? String,
           let url = mark(title: (ep["payload"] as? [String: Any])?["title"] as? String ?? "") {
          return (nil, Mark(session: s, block: b, url: url))
        }
      default: break
      }
    default: break
    }
    return (nil, nil)
  }

  static var version: String?
  static func checkVersion() {
    queue.async {
      let v = run(["version"]).map { String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) }
      DispatchQueue.main.async { version = v }
      if v == nil { log("can't run rex at \(config.rexBin); set rex_bin in ~/.rexweb/config.json") }
    }
  }

  struct Grid { let columns, rows, cellWidth, cellHeight: Double }

  static func size(block: String, session: String, host: String?) -> (displayed: Bool, grid: Grid?)? {
    guard let data = run(["block", "call", "-s", session, "-b", block, "size"], host: host),
          let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    let shown = !((o["desired"] as? [Any]) ?? []).isEmpty
    func n(_ k: String) -> Double? { (o[k] as? NSNumber)?.doubleValue }
    guard let c = n("columns"), let r = n("rows"), let w = n("cell_width_px"), let h = n("cell_height_px") else { return (shown, nil) }
    return (shown, Grid(columns: c, rows: r, cellWidth: w, cellHeight: h))
  }

  static let labelQueue = DispatchQueue(label: "rexweb.label")
  static var pendingLabels: [String: (String, String?, String)] = [:]
  static let labelLock = NSLock()

  static func setLabel(block: String, session: String, host: String?, _ label: String) {
    labelLock.lock(); pendingLabels[block] = (session, host, label); labelLock.unlock()
    labelQueue.async {
      labelLock.lock(); let next = pendingLabels.removeValue(forKey: block); labelLock.unlock()
      guard let (session, host, label) = next else { return }
      run(["block", "rename", "-s", session, block, label], host: host)
    }
  }
}

final class OverlayWindow: NSWindow {
  override var canBecomeKey: Bool { true }
  override var canBecomeMain: Bool { true }
}

final class Panel: NSObject, WKNavigationDelegate, WKUIDelegate, NSTextFieldDelegate {
  let id: String
  let session: String
  /// The address of the Rex server that holds the pane, or nil for the local server.
  let host: String?
  /// For a pane that `rexweb-remote hold` keeps, the last URL written to it; nil for a pane that registered itself.
  var reported: String?
  let window: OverlayWindow
  let web: WKWebView
  let bar = NSView()
  let urlField = NSTextField()
  let backButton = NSButton()
  let forwardButton = NSButton()
  let reloadButton = NSButton()
  var loadWaiters: [(String?) -> Void] = []
  var lastError: String?
  var requested: URL?
  var lastLabel = ""
  var visible = false
  var lastFrame = NSRect.zero
  var layoutKey = ""
  var settleUntil = Date.distantPast
  var lastActive = Date()
  var focusedInRex = false
  var pendingFocus = false
  var focusURLWhenShown = false

  static let barHeight: CGFloat = 30
  static let store = WKWebsiteDataStore(forIdentifier: UUID(uuidString: "6F1C0D2A-9C3B-4E55-9B7A-5E3B0AEB0001")!)

  init(id: String, session: String, host: String?) {
    self.id = id
    self.session = session
    self.host = host
    let conf = WKWebViewConfiguration()
    conf.websiteDataStore = Panel.store
    conf.applicationNameForUserAgent = "Version/26.4 Safari/605.1.15"
    conf.preferences.isElementFullscreenEnabled = true
    conf.allowsAirPlayForMediaPlayback = true
    web = WKWebView(frame: .zero, configuration: conf)
    window = OverlayWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300),
                           styleMask: [.borderless], backing: .buffered, defer: false)
    super.init()

    window.isReleasedWhenClosed = false
    window.hasShadow = false
    window.backgroundColor = .clear
    window.isOpaque = false
    window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]

    let root = NSView()
    root.wantsLayer = true
    root.layer?.cornerRadius = 10
    root.layer?.maskedCorners = [.layerMinXMinYCorner, .layerMaxXMinYCorner]
    root.layer?.masksToBounds = true
    root.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
    window.contentView = root

    web.navigationDelegate = self
    web.uiDelegate = self
    web.isInspectable = true
    web.allowsBackForwardNavigationGestures = true
    web.allowsMagnification = true

    for (b, sym, tip, sel) in [(backButton, "chevron.left", "Back", #selector(goBack)),
                               (forwardButton, "chevron.right", "Forward", #selector(goForward)),
                               (reloadButton, "arrow.clockwise", "Reload", #selector(reload))] {
      b.image = NSImage(systemSymbolName: sym, accessibilityDescription: tip)
      b.bezelStyle = .accessoryBarAction
      b.isBordered = false
      b.toolTip = tip
      b.target = self
      b.action = sel
      bar.addSubview(b)
    }
    urlField.placeholderString = "Search or enter address"
    urlField.font = .systemFont(ofSize: 12)
    urlField.bezelStyle = .roundedBezel
    urlField.focusRingType = .none
    urlField.lineBreakMode = .byTruncatingTail
    urlField.usesSingleLineMode = true
    urlField.delegate = self
    urlField.target = self
    urlField.action = #selector(submitURL)
    bar.addSubview(urlField)

    root.addSubview(bar)
    root.addSubview(web)
    layout()
    NotificationCenter.default.addObserver(forName: NSWindow.didResizeNotification, object: window, queue: .main) { [weak self] _ in
      self?.layout()
    }
    NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: window, queue: .main) { [weak self] _ in
      guard let self else { return }
      self.lastActive = Date()
      Rex.async(["focus", "-s", self.session, self.id], host: self.host)
    }
    web.addObserver(self, forKeyPath: "title", options: .new, context: nil)
    web.addObserver(self, forKeyPath: "URL", options: .new, context: nil)
    web.addObserver(self, forKeyPath: "canGoBack", options: .new, context: nil)
    web.addObserver(self, forKeyPath: "canGoForward", options: .new, context: nil)
    updateChrome()
  }

  func layout() {
    guard let root = window.contentView else { return }
    let b = root.bounds
    let h = Panel.barHeight
    bar.frame = NSRect(x: 0, y: b.height - h, width: b.width, height: h)
    backButton.frame = NSRect(x: 6, y: 4, width: 24, height: 22)
    forwardButton.frame = NSRect(x: 30, y: 4, width: 24, height: 22)
    reloadButton.frame = NSRect(x: 54, y: 4, width: 24, height: 22)
    urlField.frame = NSRect(x: 84, y: 4, width: max(40, b.width - 92), height: 22)
    web.frame = NSRect(x: 0, y: 0, width: b.width, height: max(0, b.height - h))
  }

  override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
    updateChrome()
  }

  func updateChrome() {
    backButton.isEnabled = web.canGoBack
    forwardButton.isEnabled = web.canGoForward
    if window.firstResponder != urlField.currentEditor() {
      urlField.stringValue = web.url?.absoluteString ?? ""
    }
    if let r = reported, let u = web.url?.absoluteString, u != r {
      reported = u
      Rex.async(["block", "call", "-s", session, "-b", id, "write", Rex.json(["data": u + "\n"])], host: host)
    }
    guard let title = (web.title?.isEmpty == false ? web.title : web.url?.host), !title.isEmpty else { return }
    let label = String(title.prefix(80))
    if label != lastLabel {
      lastLabel = label
      Rex.setLabel(block: id, session: session, host: host, host == nil ? label : "rexweb " + label)
    }
  }

  func info() -> [String: Any] {
    ["id": id, "session": session, "host": orNull(host), "url": web.url?.absoluteString ?? "", "title": web.title ?? "",
     "loading": web.isLoading, "visible": visible, "error": orNull(lastError)]
  }

  static func normalize(_ raw: String) -> URL? {
    let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    if s.isEmpty { return nil }
    if s.contains("://") || s.hasPrefix("about:") || s.hasPrefix("data:") { return URL(string: s) }
    if s.hasPrefix("localhost") || s.hasPrefix("127.") || s.hasPrefix("[::1]") || s.range(of: #"^\d+$"#, options: .regularExpression) != nil {
      let hostPort = s.range(of: #"^\d+$"#, options: .regularExpression) != nil ? "localhost:\(s)" : s
      return URL(string: "http://" + hostPort)
    }
    if !s.contains(" ") && s.contains(".") { return URL(string: "https://" + s) }
    let q = s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&+=?#"))) ?? s
    return URL(string: config.searchURL.replacingOccurrences(of: "%s", with: q))
  }

  func load(_ raw: String, done: ((String?) -> Void)? = nil) {
    guard let url = Panel.normalize(raw) else { done?("bad url"); return }
    requested = url
    if let done { loadWaiters.append(done) }
    if url.isFileURL {
      web.loadFileURL(url, allowingReadAccessTo: URL(fileURLWithPath: "/"))
    } else {
      web.load(URLRequest(url: url))
    }
  }

  var refusedError: String? {
    guard let req = requested, req.scheme != "about", web.url == nil || web.url?.absoluteString == "about:blank" else { return nil }
    return "WebKit didn't load \(req.absoluteString). Its port may be one WebKit blocks"
  }

  func waitForLoad(_ done: @escaping (String?) -> Void) {
    if !web.isLoading { done(lastError ?? refusedError); return }
    loadWaiters.append(done)
  }

  func finishWaiters(_ err: String?) {
    let w = loadWaiters
    loadWaiters = []
    w.forEach { $0(err) }
  }

  @objc func goBack() { web.goBack() }
  @objc func goForward() { web.goForward() }
  @objc func reload() { web.reload() }
  @objc func submitURL() {
    load(urlField.stringValue)
    window.makeFirstResponder(web)
  }

  func focusURL() {
    window.makeFirstResponder(urlField)
    urlField.currentEditor()?.selectAll(nil)
  }

  func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) { lastError = nil }
  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { lastError = nil; finishWaiters(nil); updateChrome() }
  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failed(error) }
  func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failed(error) }

  func failed(_ error: Error) {
    let e = error as NSError
    if e.domain == NSURLErrorDomain && e.code == NSURLErrorCancelled { return }
    lastError = e.localizedDescription
    finishWaiters(lastError)
  }

  var popups: [Popup] = []

  func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
               for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
    let isPopup = windowFeatures.width != nil || windowFeatures.height != nil || navigationAction.navigationType == .other
    if !isPopup {
      if let url = navigationAction.request.url { webView.load(URLRequest(url: url)) }
      return nil
    }
    let popup = Popup(configuration: configuration, features: windowFeatures, parent: window)
    popup.onClose = { [weak self, weak popup] in self?.popups.removeAll { $0 === popup } }
    popups.append(popup)
    return popup.web
  }

  func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
               decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
    if navigationAction.modifierFlags.contains(.command), let url = navigationAction.request.url,
       navigationAction.navigationType == .linkActivated {
      App.shared.openPane(beside: self, url: url.absoluteString)
      decisionHandler(.cancel)
      return
    }
    decisionHandler(.allow)
  }

  func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
               initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
    let a = NSAlert(); a.messageText = message; a.beginSheetModal(for: window) { _ in completionHandler() }
  }

  func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
               initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
    let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
    a.beginSheetModal(for: window) { completionHandler($0 == .alertFirstButtonReturn) }
  }

  func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
               initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
    let p = NSOpenPanel(); p.allowsMultipleSelection = parameters.allowsMultipleSelection
    p.canChooseDirectories = parameters.allowsDirectories
    p.beginSheetModal(for: window) { completionHandler($0 == .OK ? p.urls : nil) }
  }

  func close() {
    popups.forEach { $0.window.close() }
    popups = []
    finishWaiters("closed")
    for k in ["title", "URL", "canGoBack", "canGoForward"] { web.removeObserver(self, forKeyPath: k) }
    window.orderOut(nil)
    window.close()
  }
}

final class Popup: NSObject, WKUIDelegate, WKNavigationDelegate, NSWindowDelegate {
  let web: WKWebView
  let window: NSWindow
  var onClose: (() -> Void)?

  init(configuration: WKWebViewConfiguration, features: WKWindowFeatures, parent: NSWindow) {
    let w = CGFloat(features.width?.doubleValue ?? 520), h = CGFloat(features.height?.doubleValue ?? 680)
    web = WKWebView(frame: NSRect(x: 0, y: 0, width: w, height: h), configuration: configuration)
    window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: w, height: h),
                      styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
    super.init()
    window.isReleasedWhenClosed = false
    window.contentView = web
    window.delegate = self
    web.uiDelegate = self
    web.navigationDelegate = self
    web.isInspectable = true
    let pf = parent.frame
    window.setFrameOrigin(NSPoint(x: pf.midX - w / 2, y: pf.midY - h / 2))
    window.level = .floating
    window.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  func webViewDidClose(_ webView: WKWebView) { window.close() }
  func windowWillClose(_ n: Notification) { onClose?() }
  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { window.title = webView.title ?? "" }
}

enum ChromeCookies {
  static let root = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/Google/Chrome")

  static func database(profile: String?) throws -> URL {
    let fm = FileManager.default
    let profiles = profile.map { [$0] } ?? ((try? fm.contentsOfDirectory(atPath: root.path)) ?? [])
    var found: [(URL, Date)] = []
    for p in profiles {
      for name in ["Network/Cookies", "Cookies"] {
        let u = root.appendingPathComponent(p).appendingPathComponent(name)
        if let a = try? fm.attributesOfItem(atPath: u.path), let d = a[.modificationDate] as? Date { found.append((u, d)) }
      }
    }
    guard let newest = found.max(by: { $0.1 < $1.1 }) else {
      throw NSError(domain: "rexweb", code: 1, userInfo: [NSLocalizedDescriptionKey: "no Chrome cookies database found"])
    }
    return newest.0
  }

  static func key() throws -> Data {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
    p.arguments = ["find-generic-password", "-a", "Chrome", "-s", "Chrome Safe Storage", "-w"]
    let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
    try p.run(); p.waitUntilExit()
    let secret = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
      .trimmingCharacters(in: .whitespacesAndNewlines)
    guard p.terminationStatus == 0, !secret.isEmpty else {
      throw NSError(domain: "rexweb", code: 2, userInfo: [NSLocalizedDescriptionKey: "couldn't read Chrome Safe Storage from the Keychain"])
    }
    var derived = Data(count: 16)
    let salt = Array("saltysalt".utf8)
    _ = derived.withUnsafeMutableBytes { d in
      CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), secret, secret.utf8.count, salt, salt.count,
                           CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003, d.bindMemory(to: UInt8.self).baseAddress, 16)
    }
    return derived
  }

  static func decrypt(_ blob: Data, key: Data, integrityPrefix: Bool) -> String? {
    guard blob.count > 3, let tag = String(data: blob.prefix(3), encoding: .ascii), tag == "v10" || tag == "v20" else { return nil }
    let cipher = blob.dropFirst(3)
    var out = Data(count: cipher.count + kCCBlockSizeAES128)
    var moved = 0
    let iv = [UInt8](repeating: 0x20, count: 16)
    let outCount = out.count
    let status = out.withUnsafeMutableBytes { o in
      cipher.withUnsafeBytes { c in
        key.withUnsafeBytes { k in
          CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                  k.baseAddress, key.count, iv, c.baseAddress, cipher.count, o.baseAddress, outCount, &moved)
        }
      }
    }
    guard status == kCCSuccess else { return nil }
    var plain = out.prefix(moved)
    if integrityPrefix { plain = plain.dropFirst(32) }
    return String(data: plain, encoding: .utf8)
  }

  static func read(profile: String?, domains: [String]) throws -> (cookies: [HTTPCookie], skipped: Int) {
    let src = try database(profile: profile)
    let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("rexweb-cookies-\(UUID().uuidString)")
    try FileManager.default.copyItem(at: src, to: tmp)
    defer { try? FileManager.default.removeItem(at: tmp) }
    var db: OpaquePointer?
    guard sqlite3_open_v2(tmp.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
      throw NSError(domain: "rexweb", code: 3, userInfo: [NSLocalizedDescriptionKey: "couldn't open Chrome's cookies database"])
    }
    defer { sqlite3_close(db) }
    func query(_ sql: String, _ row: (OpaquePointer) -> Void) {
      var st: OpaquePointer?
      guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK, let st else { return }
      while sqlite3_step(st) == SQLITE_ROW { row(st) }
      sqlite3_finalize(st)
    }
    var version = 0
    query("SELECT value FROM meta WHERE key = 'version'") { version = Int(String(cString: sqlite3_column_text($0, 0))) ?? 0 }
    let k = try key()
    let now = Date()
    var cookies: [HTTPCookie] = []
    var skipped = 0
    let wanted = domains.map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
    query("SELECT host_key, name, path, is_secure, is_httponly, expires_utc, encrypted_value, samesite FROM cookies") { st in
      let host = String(cString: sqlite3_column_text(st, 0))
      let bare = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
      if !wanted.isEmpty && !wanted.contains(where: { bare == $0 || bare.hasSuffix("." + $0) }) { return }
      let len = Int(sqlite3_column_bytes(st, 6))
      guard len > 0, let ptr = sqlite3_column_blob(st, 6) else { return }
      guard let value = decrypt(Data(bytes: ptr, count: len), key: k, integrityPrefix: version >= 24) else { skipped += 1; return }
      let expiresUTC = sqlite3_column_int64(st, 5)
      var props: [HTTPCookiePropertyKey: Any] = [
        .domain: host, .name: String(cString: sqlite3_column_text(st, 1)), .value: value,
        .path: { let p = String(cString: sqlite3_column_text(st, 2)); return p.isEmpty ? "/" : p }(),
      ]
      if expiresUTC > 0 {
        let expires = Date(timeIntervalSince1970: Double(expiresUTC - 11_644_473_600_000_000) / 1e6)
        if expires < now { return }
        props[.expires] = expires
      }
      if sqlite3_column_int(st, 3) == 1 { props[.secure] = "TRUE" }
      if sqlite3_column_int(st, 4) == 1 { props[HTTPCookiePropertyKey("HttpOnly")] = "TRUE" }
      switch sqlite3_column_int(st, 7) {
      case 0: props[.sameSitePolicy] = "none"
      case 1: props[.sameSitePolicy] = HTTPCookieStringPolicy.sameSiteLax.rawValue
      case 2: props[.sameSitePolicy] = HTTPCookieStringPolicy.sameSiteStrict.rawValue
      default: break
      }
      if let c = HTTPCookie(properties: props) { cookies.append(c) }
    }
    return (cookies, skipped)
  }
}

struct RexWindow { let number: Int; let name: String; let bounds: CGRect }

final class Tracker {
  var views: [String: [String: Any]] = [:]
  var displayed: [String: Bool] = [:]
  var grids: [String: Rex.Grid] = [:]
  var windowSession: [Int: String] = [:]
  var pendingPair: (Int, String)?
  var refreshing = Set<String>()
  var dirty = Set<String>()
  /// One `rex events` stream per server: "" for the local server, else a host's address.
  var streams: [String: Process] = [:]
  var hosts = Set<String>()
  var rexWasActive = false
  var insets = RexChrome.read()

  func start() {
    Timer.scheduledTimer(withTimeInterval: 1.0 / 60.0, repeats: true) { [weak self] _ in self?.tick() }
    Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
      self?.insets = RexChrome.read()
      self?.learnWindows()
    }
    Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in self?.refreshAll() }
    Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in self?.syncHosts() }
    startEvents(nil)
    syncHosts()
  }

  /// Follow every host in the local server's host list, and stop following hosts that left it.
  func syncHosts() {
    Rex.queue.async {
      guard let list = Rex.hosts() else { return }
      DispatchQueue.main.async {
        let now = Set(list)
        for h in self.hosts.subtracting(now) { self.streams.removeValue(forKey: h)?.terminate() }
        let added = now.subtracting(self.hosts)
        self.hosts = now
        added.forEach { self.startEvents($0) }
      }
    }
  }

  /// Stream a server's events: a layout change refreshes that session's panels, and on another host a marked,
  /// labelled pane becomes a panel. Each time a host's stream starts, a scan adopts the marked panes already there.
  /// Local panes register themselves through `rexweb-pane`.
  func startEvents(_ host: String?) {
    let p = Rex.process(["events", "--all", "--json"], host: host)
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    var buf = Data(), cli = Set<String>()
    out.fileHandleForReading.readabilityHandler = { [weak self] h in
      let d = h.availableData
      if d.isEmpty { h.readabilityHandler = nil; return }
      buf.append(d)
      var marks: [Rex.Mark] = [], sessions = Set<String>()
      while let nl = buf.firstIndex(of: 10) {
        let e = Rex.event(buf[buf.startIndex..<nl], cli: &cli)
        if let s = e.session { sessions.insert(s) }
        if let m = e.mark, host != nil { marks.append(m) }
        buf = Data(buf[(nl + 1)...])
      }
      DispatchQueue.main.async {
        for m in marks where App.shared.panels[m.block] == nil {
          Rex.queue.async {
            guard Rex.labelled(m, host: host) else { return }
            DispatchQueue.main.async { App.shared.adopt(m, host: host) }
          }
        }
        sessions.forEach { self?.refresh($0) }
      }
    }
    let started = Date()
    p.terminationHandler = { [weak self] _ in
      let delay = host != nil && Date().timeIntervalSince(started) < 10 ? 30.0 : 2.0
      DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
        guard let self, host.map(self.hosts.contains) ?? true else { return }
        self.startEvents(host)
      }
    }
    do { try p.run() } catch { log("events failed: \(error)"); return }
    streams[host ?? ""] = p
    guard host != nil else { return }
    Rex.queue.async {
      let marks = Rex.scan(host: host)
      DispatchQueue.main.async { marks.forEach { App.shared.adopt($0, host: host) } }
    }
  }

  func refreshAll() {
    Set(App.shared.panels.values.map(\.session)).forEach(refresh)
  }

  func refresh(_ session: String) {
    let mine = App.shared.panels.values.filter { $0.session == session }
    if mine.isEmpty { return }
    if refreshing.contains(session) { dirty.insert(session); return }
    refreshing.insert(session)
    let ids = mine.map(\.id), host = mine.first?.host
    Rex.queue.async {
      let v = Rex.view(session, host: host)
      var shown: [String: Bool] = [:]
      var grids: [String: Rex.Grid] = [:]
      for id in ids {
        guard let sz = Rex.size(block: id, session: session, host: host) else { continue }
        shown[id] = sz.displayed
        if let g = sz.grid { grids[id] = g }
      }
      DispatchQueue.main.async {
        self.refreshing.remove(session)
        for (id, d) in shown { self.displayed[id] = d }
        for (id, g) in grids { self.grids[id] = g }
        if let v { self.views[session] = v; self.reconcile(session) }
        if self.dirty.remove(session) != nil { self.refresh(session) }
      }
    }
  }

  func reconcile(_ session: String) {
    guard let v = views[session] else { return }
    let ids = Set(Tracker.allBlockIDs(v))
    for p in App.shared.panels.values where p.session == session && !ids.contains(p.id) {
      App.shared.closePanel(p.id)
    }
  }

  static func allBlockIDs(_ v: [String: Any]) -> [String] {
    var out: [String] = []
    for w in v["windows"] as? [[String: Any]] ?? [] {
      for l in w["layers"] as? [[String: Any]] ?? [] {
        for b in l["blocks"] as? [[String: Any]] ?? [] { if let id = b["block_id"] as? String { out.append(id) } }
      }
    }
    return out
  }

  static func rexWindows() -> (rex: [RexWindow], order: [Int]) {
    let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
    var rex: [RexWindow] = []
    var order: [Int] = []
    for w in list {
      guard let n = w[kCGWindowNumber as String] as? Int else { continue }
      order.append(n)
      let owner = w[kCGWindowOwnerName as String] as? String ?? ""
      let layer = w[kCGWindowLayer as String] as? Int ?? 0
      guard layer == 0, owner == "Rex" || owner.hasPrefix("Rex ") else { continue }
      guard let bd = w[kCGWindowBounds as String] as? NSDictionary,
            let r = CGRect(dictionaryRepresentation: bd), r.width > 200, r.height > 200 else { continue }
      rex.append(RexWindow(number: n, name: w[kCGWindowName as String] as? String ?? "", bounds: r))
    }
    return (rex, order)
  }

  static func placement(of id: String, in view: [String: Any]) -> (rect: CGRect, floating: Bool)? {
    guard let active = view["active_window_id"] as? String,
          let windows = view["windows"] as? [[String: Any]],
          let win = windows.first(where: { w in
            (w["layers"] as? [[String: Any]] ?? []).contains { l in
              (l["blocks"] as? [[String: Any]] ?? []).contains { $0["block_id"] as? String == id }
            }
          }),
          win["window_id"] as? String == active else { return nil }
    if let z = win["zoomed_block_id"] as? String, !z.isEmpty {
      return z == id ? (CGRect(x: 0, y: 0, width: 1, height: 1), false) : nil
    }
    for l in win["layers"] as? [[String: Any]] ?? [] {
      if let r = find(id, in: l["layout"]) {
        if l["kind"] as? String == "tiled" { return (r, false) }
        if (l["state"] as? String) == "minimized" { return nil }
        return (r, true)
      }
    }
    return nil
  }

  static func rect(_ any: Any?) -> CGRect? {
    guard let a = any as? [NSNumber], a.count == 4 else { return nil }
    return CGRect(x: a[0].doubleValue, y: a[1].doubleValue, width: a[2].doubleValue, height: a[3].doubleValue)
  }

  static func find(_ id: String, in node: Any?) -> CGRect? {
    if let d = node as? [String: Any] {
      if d["block_id"] as? String == id { return rect(d["rect"]) }
      for (_, v) in d { if let r = find(id, in: v) { return r } }
    } else if let a = node as? [Any] {
      for v in a { if let r = find(id, in: v) { return r } }
    }
    return nil
  }

  static func focused(in view: [String: Any]) -> String? {
    guard let active = view["active_window_id"] as? String,
          let w = (view["windows"] as? [[String: Any]])?.first(where: { $0["window_id"] as? String == active }) else { return nil }
    return w["focused_block_id"] as? String
  }

  func tick() {
    let panels = App.shared.panels.values
    if panels.isEmpty { return }
    let (rexWins, order) = Tracker.rexWindows()
    let rexActive = NSWorkspace.shared.frontmostApplication?.bundleIdentifier?.hasPrefix("com.superlogical.rex") == true
    let primaryHeight = NSScreen.screens.first?.frame.height ?? 0

    for p in panels {
      guard displayed[p.id] == true, let v = views[p.session], let place = Tracker.placement(of: p.id, in: v) else { hide(p); continue }
      let ins = insets
      let frac = place.rect
      guard let rw = window(for: p, place, v, rexWins, primaryHeight) else { hide(p); continue }

      let key = "\(frac) \(place.floating) \(rw.number)"
      if key != p.layoutKey {
        p.layoutKey = key
        p.settleUntil = Date().addingTimeInterval(0.4)
        if p.window.isKeyWindow { p.pendingFocus = true }
      }
      if Date() < p.settleUntil { hide(p); continue }
      let (body, radius) = Tracker.body(frac, floating: place.floating, in: rw.bounds, ins)
      if let l = p.window.contentView?.layer, l.cornerRadius != CGFloat(radius) { l.cornerRadius = CGFloat(radius) }
      guard body.width > 20, body.height > 20 else { hide(p); continue }
      let x0 = (body.minX).rounded(.up), x1 = (body.maxX).rounded(.down)
      let y0 = (body.minY).rounded(.up), y1 = (body.maxY).rounded(.down)
      let ns = NSRect(x: x0, y: primaryHeight - y1, width: x1 - x0, height: y1 - y0)
      if ns != p.lastFrame { p.window.setFrame(ns, display: true); p.lastFrame = ns }

      let mine = p.window.windowNumber
      let iMine = order.firstIndex(of: mine), iRex = order.firstIndex(of: rw.number)
      let ours = Set(App.shared.panels.values.map { $0.window.windowNumber })
      var stacked = false
      if let iMine, let iRex, iMine < iRex {
        stacked = order[(iMine + 1)..<iRex].allSatisfy { ours.contains($0) }
      }
      if !p.visible || !stacked { p.window.order(.above, relativeTo: rw.number) }
      p.visible = true
      if p.pendingFocus {
        p.pendingFocus = false
        App.shared.focus(p)
      }

      let isFocused = Tracker.focused(in: v) == p.id
      if isFocused && !p.focusedInRex && rexActive {
        App.shared.focus(p)
      }
      p.focusedInRex = isFocused
    }
    rexWasActive = rexActive
  }

  func learnWindows() {
    let wins = Tracker.rexWindows().rex
    let live = Set(wins.map(\.number))
    windowSession = windowSession.filter { live.contains($0.key) }
    let rexActive = NSWorkspace.shared.frontmostApplication?.bundleIdentifier?.hasPrefix("com.superlogical.rex") == true
    guard rexActive, let front = wins.first,
          let data = RexChrome.value("lastFocusedSession") as? Data,
          let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let session = o["sessionID"] as? String else { pendingPair = nil; return }
    if let p = pendingPair, p.0 == front.number, p.1 == session {
      windowSession = windowSession.filter { $0.value != session }
      windowSession[front.number] = session
    }
    pendingPair = (front.number, session)
  }

  func window(for p: Panel, _ place: (rect: CGRect, floating: Bool), _ v: [String: Any], _ rexWins: [RexWindow], _ primaryHeight: CGFloat) -> RexWindow? {
    let label = v["label"] as? String ?? ""
    if let w = rexWins.first(where: { !$0.name.isEmpty && ($0.name == label || $0.name.hasSuffix(" - \(label)")) }) { return w }
    if let w = rexWins.first(where: { windowSession[$0.number] == p.session }) { return w }
    let free = rexWins.filter { windowSession[$0.number] == nil }
    if free.count == 1 { return free[0] }
    guard free.count > 1, let g = grids[p.id] else { return nil }
    let ranked = free.map { ($0, score($0)) }.sorted { $0.1 < $1.1 }
    return ranked[1].1 - ranked[0].1 > 2 ? ranked[0].0 : nil
    func score(_ w: RexWindow) -> Double {
      let body = Tracker.body(place.rect, floating: place.floating, in: w.bounds, insets).body
      let s = Tracker.scale(at: w.bounds, primaryHeight: primaryHeight)
      return abs(body.width - g.columns * g.cellWidth / s) + abs(body.height - g.rows * g.cellHeight / s)
    }
  }

  static func body(_ frac: CGRect, floating: Bool, in b: CGRect, _ ins: Insets) -> (body: CGRect, radius: Double) {
    let area = floating
      ? CGRect(x: b.minX + ins.floatLeft, y: b.minY + ins.floatTop,
               width: b.width - ins.floatLeft - ins.floatRight, height: b.height - ins.floatTop)
      : CGRect(x: b.minX + ins.left, y: b.minY + ins.top,
               width: b.width - ins.left - ins.right, height: b.height - ins.top - ins.bottom)
    var card = CGRect(x: area.minX + frac.minX * area.width, y: area.minY + frac.minY * area.height,
                      width: frac.width * area.width, height: frac.height * area.height)
    var header = ins.header, radius = ins.radius
    if floating {
      card = card.insetBy(dx: 2, dy: 2)
      header = ins.floatHeader; radius = 10
    } else {
      let g = ins.gap / 2, eps = 0.001
      if frac.minX > eps { card.origin.x += g; card.size.width -= g }
      if frac.maxX < 1 - eps { card.size.width -= g }
      if frac.minY > eps { card.origin.y += g; card.size.height -= g }
      if frac.maxY < 1 - eps { card.size.height -= g }
    }
    return (CGRect(x: card.minX, y: card.minY + header, width: card.width, height: card.height - header), radius)
  }

  static func scale(at r: CGRect, primaryHeight: CGFloat) -> Double {
    let center = NSPoint(x: r.midX, y: primaryHeight - r.midY)
    return Double(NSScreen.screens.first { $0.frame.contains(center) }?.backingScaleFactor ?? 2)
  }

  func hide(_ p: Panel) {
    if p.visible { p.window.orderOut(nil); p.visible = false }
  }
}

final class Server {
  var listener: NWListener!

  static func refuse(method: String, path: String, headers: [String: String]) -> (Int, String)? {
    if headers["origin"] != nil || headers["sec-fetch-site"] != nil || headers["sec-fetch-mode"] != nil {
      return (403, "rexweb doesn't accept requests from web pages")
    }
    let host = headers["host"] ?? ""
    guard host == "127.0.0.1:\(config.port)" || host == "localhost:\(config.port)" else {
      return (403, "rexweb only accepts requests to 127.0.0.1:\(config.port)")
    }
    guard method == "POST" else { return (405, "use POST") }
    let route = path.split(separator: "?").first.map(String.init) ?? path
    if route == "/health" { return nil }
    guard Auth.matches(headers["x-rexweb-token"]) else {
      return (401, "missing or wrong token; send the contents of ~/.rexweb/token in an x-rexweb-token header")
    }
    return nil
  }

  func start() {
    do {
      let params = NWParameters.tcp
      params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(config.port))!)
      params.allowLocalEndpointReuse = true
      listener = try NWListener(using: params)
    } catch { log("listen failed: \(error)"); exit(1) }
    listener.newConnectionHandler = { conn in
      conn.start(queue: .main)
      self.read(conn, Data())
    }
    listener.stateUpdateHandler = { st in
      if case .failed(let e) = st { log("listener failed: \(e)"); exit(1) }
    }
    listener.start(queue: .main)
  }

  func read(_ conn: NWConnection, _ sofar: Data) {
    conn.receive(minimumIncompleteLength: 1, maximumLength: 1 << 22) { data, _, done, _ in
      var buf = sofar
      if let data { buf.append(data) }
      guard let split = buf.range(of: Data("\r\n\r\n".utf8)) else {
        return done ? conn.cancel() : self.read(conn, buf)
      }
      let head = String(decoding: buf[..<split.lowerBound], as: UTF8.self)
      let lines = head.split(separator: "\r\n")
      var headers: [String: String] = [:]
      for line in lines.dropFirst() {
        guard let c = line.firstIndex(of: ":") else { continue }
        headers[line[..<c].lowercased()] = line[line.index(after: c)...].trimmingCharacters(in: .whitespaces)
      }
      let length = Int(headers["content-length"] ?? "") ?? 0
      let body = buf[split.upperBound...]
      if body.count < length && !done { return self.read(conn, buf) }
      let request = lines.first?.split(separator: " ") ?? []
      let method = request.first.map(String.init) ?? ""
      let path = request.dropFirst().first.map(String.init) ?? "/"
      let respond = { (status: Int, out: Any) in
        let bytes = (try? JSONSerialization.data(withJSONObject: out, options: [.fragmentsAllowed])) ?? Data("{}".utf8)
        let top = "HTTP/1.1 \(status) X\r\ncontent-type: application/json\r\ncontent-length: \(bytes.count)\r\nconnection: close\r\n\r\n"
        conn.send(content: Data(top.utf8) + bytes, completion: .contentProcessed { _ in conn.cancel() })
      }
      if let refusal = Server.refuse(method: method, path: path, headers: headers) { return respond(refusal.0, ["error": refusal.1]) }
      let input = (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any] ?? [:]
      App.shared.handle(path: path, input: input, reply: respond)
    }
  }
}

enum JS {
  static let snapshot = #"""
  const max = args.max || 400;
  const sel = 'a[href],button,input,textarea,select,summary,[role=button],[role=link],[role=checkbox],[role=tab],[role=menuitem],[role=option],[role=switch],[contenteditable=""],[contenteditable=true],[onclick],[tabindex]:not([tabindex="-1"])';
  const vis = el => { const r = el.getBoundingClientRect(); const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const name = el => (el.getAttribute('aria-label') || el.labels?.[0]?.innerText || el.innerText || el.value ||
    el.getAttribute('placeholder') || el.getAttribute('title') || el.getAttribute('alt') || el.getAttribute('name') || '')
    .replace(/\s+/g, ' ').trim().slice(0, 80);
  document.querySelectorAll('[data-rexweb-ref]').forEach(e => e.removeAttribute('data-rexweb-ref'));
  const lines = []; let n = 0;
  for (const el of document.querySelectorAll(sel)) {
    if (n >= max || !vis(el)) continue;
    const ref = 'e' + (++n); el.setAttribute('data-rexweb-ref', ref);
    const tag = el.tagName.toLowerCase();
    const role = el.getAttribute('role') || (tag === 'a' ? 'link' : tag === 'input' ? (el.type || 'text') : tag);
    let extra = '';
    if (tag === 'a') extra = ' -> ' + el.getAttribute('href');
    if ('checked' in el && (el.type === 'checkbox' || el.type === 'radio')) extra += el.checked ? ' [checked]' : ' [ ]';
    if ((tag === 'textarea' || (tag === 'input' && !['checkbox','radio','password','hidden','submit','button'].includes(el.type))) && el.value) extra += ' value=' + JSON.stringify(el.value.slice(0, 60));
    if (el.disabled) extra += ' [disabled]';
    lines.push(`[${ref}] ${role} "${name(el)}"${extra}`);
  }
  const text = (document.body?.innerText || '').replace(/\n{3,}/g, '\n\n').slice(0, args.textMax || 6000);
  return { url: location.href, title: document.title, elements: lines.join('\n'), text };
  """#

  static let resolve = #"""
  const t = args.target;
  const el = /^@?e\d+$/.test(t) ? document.querySelector(`[data-rexweb-ref="${t.replace('@','')}"]`) : document.querySelector(t);
  if (!el) return { error: 'no element for ' + t + ' (run snapshot first for e-refs)' };
  el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
  const r = el.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2, tag: el.tagName.toLowerCase() };
  """#

  static let fill = #"""
  const t = args.target;
  let el = t ? (/^@?e\d+$/.test(t) ? document.querySelector(`[data-rexweb-ref="${t.replace('@','')}"]`) : document.querySelector(t)) : document.activeElement;
  if (!el) return { error: 'no element for ' + t };
  el.focus();
  if (el.isContentEditable) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(range);
    if (args.clear) { document.execCommand('delete'); } else { sel.collapseToEnd(); }
    return { native: true };
  } else {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    const set = Object.getOwnPropertyDescriptor(proto, 'value').set;
    set.call(el, (args.clear ? '' : el.value) + args.text);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }
  if (args.submit) {
    const f = el.form; if (f) { f.requestSubmit ? f.requestSubmit() : f.submit(); }
    else el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true }));
  }
  return { ok: true };
  """#

  static func evaluate(_ code: String, asExpression: Bool) -> String {
    let body = asExpression ? "return (\n\(code)\n);" : code
    return """
    const __v = await (async () => { \(body) })();
    try { return JSON.parse(JSON.stringify(__v === undefined ? null : __v)); } catch (e) { return String(__v); }
    """
  }

  static let exists = #"""
  if (args.selector) return !!document.querySelector(args.selector);
  if (args.text) return (document.body?.innerText || '').includes(args.text);
  return document.readyState === 'complete';
  """#
}

enum Links {
  static let fallbackFile = Config.dir.appendingPathComponent("fallback-browser")
  static let selfID = Bundle.main.bundleIdentifier ?? "dev.coey.rexweb"

  static var fallbackID: String {
    if !config.fallbackBrowser.isEmpty { return config.fallbackBrowser }
    if let saved = try? String(contentsOf: fallbackFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
       !saved.isEmpty { return saved }
    for id in ["com.google.Chrome", "com.apple.Safari"] where NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) != nil {
      return id
    }
    return "com.apple.Safari"
  }

  static func forward(_ url: URL) {
    guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: fallbackID)
            ?? NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") else {
      log("no browser to pass \(url) to"); return
    }
    NSWorkspace.shared.open([url], withApplicationAt: app, configuration: NSWorkspace.OpenConfiguration())
  }

  static func frontRexSession() -> String? {
    guard let win = Tracker.rexWindows().rex.first else { return nil }
    guard let data = Rex.run(["ls", "--json"]),
          let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let sessions = o["sessions"] as? [[String: Any]] else { return nil }
    let match = sessions.filter { s in
      guard let l = s["label"] as? String, !l.isEmpty else { return false }
      return win.name == l || win.name.hasSuffix(" - \(l)")
    }.max { ($0["label"] as? String ?? "").count < ($1["label"] as? String ?? "").count }
    return match?["session_id"] as? String
  }

  static func openInRex(_ url: URL) {
    let pane = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/rexweb-pane").path
    Rex.queue.async {
      var args = config.linkTarget == "tab" ? ["run"] : ["split", "--split=right"]
      if let s = frontRexSession() { args += ["-s", s] }
      args += ["--shell=none", "--label", "browser", "--", "env", "REXWEB_FOCUS=true", pane, url.absoluteString]
      if Rex.run(args) == nil { DispatchQueue.main.async { forward(url) } }
    }
  }

  static func makeDefault(_ on: Bool, done: @escaping (String?) -> Void) {
    let probe = URL(string: "https://example.com")!
    let target: URL
    if on {
      if let current = NSWorkspace.shared.urlForApplication(toOpen: probe),
         let id = Bundle(url: current)?.bundleIdentifier, id != selfID {
        try? id.write(to: fallbackFile, atomically: true, encoding: .utf8)
      }
      target = Bundle.main.bundleURL
    } else {
      guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: fallbackID) else { return done("no browser to restore") }
      target = app
    }
    let wanted = Bundle(url: target)?.bundleIdentifier
    let check = { (err: Error?) in
      DispatchQueue.main.async {
        let now = ["http", "https"].map { NSWorkspace.shared.urlForApplication(toOpen: URL(string: "\($0)://example.com")!).flatMap { Bundle(url: $0)?.bundleIdentifier } }
        done(now.allSatisfy { $0 == wanted } ? nil : (err?.localizedDescription ?? "macOS didn't change the default browser"))
      }
    }
    NSWorkspace.shared.setDefaultApplication(at: target, toOpenURLsWithScheme: "http") { _ in
      NSWorkspace.shared.setDefaultApplication(at: target, toOpenURLsWithScheme: "https") { check($0) }
    }
  }
}

final class App: NSObject, NSApplicationDelegate {
  static let shared = App()
  var panels: [String: Panel] = [:]
  let tracker = Tracker()
  let server = Server()

  func applicationWillFinishLaunching(_ n: Notification) {
    NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(handleURLEvent(_:reply:)),
                                                 forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
  }

  @objc func handleURLEvent(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
    guard let raw = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue, let url = URL(string: raw) else { return }
    let pid = event.attributeDescriptor(forKeyword: keySenderPIDAttr)?.int32Value ?? 0
    let sender = NSRunningApplication(processIdentifier: pid)?.bundleIdentifier ?? ""
    log("link from \(sender.isEmpty ? "pid \(pid)" : sender)")
    if sender.hasPrefix("com.superlogical.rex") { Links.openInRex(url) } else { Links.forward(url) }
  }

  func application(_ sender: NSApplication, open urls: [URL]) {
    urls.forEach { Links.openInRex($0) }
  }

  func applicationDidFinishLaunching(_ n: Notification) {
    try? FileManager.default.createDirectory(at: Config.dir, withIntermediateDirectories: true)
    _ = Auth.token
    Rex.checkVersion()
    if let e = config.configError { log(e) }
    buildMenu()
    server.start()
    tracker.start()
    NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] e in self?.key(e) == true ? nil : e }
    log("listening on 127.0.0.1:\(config.port)")
  }

  func buildMenu() {
    let main = NSMenu()
    let appItem = NSMenuItem(); main.addItem(appItem)
    let appMenu = NSMenu(); appItem.submenu = appMenu
    appMenu.addItem(withTitle: "Quit RexWeb", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    let editItem = NSMenuItem(); main.addItem(editItem)
    let edit = NSMenu(title: "Edit"); editItem.submenu = edit
    edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
    let redo = edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "z")
    redo.keyEquivalentModifierMask = [.command, .shift]
    edit.addItem(.separator())
    edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    NSApp.mainMenu = main
  }

  var keyPanel: Panel? { panels.values.first { $0.window.isKeyWindow } }

  func key(_ e: NSEvent) -> Bool {
    guard let p = keyPanel else { return false }
    let m = e.modifierFlags.intersection(.deviceIndependentFlagsMask)
    let c = e.charactersIgnoringModifiers?.lowercased() ?? ""
    if m == .command {
      switch c {
      case "l": p.focusURL(); return true
      case "r": p.web.reload(); return true
      case "[": p.web.goBack(); return true
      case "]": p.web.goForward(); return true
      case "=", "+": p.web.pageZoom = min(3, p.web.pageZoom + 0.1); return true
      case "-": p.web.pageZoom = max(0.3, p.web.pageZoom - 0.1); return true
      case "0": p.web.pageZoom = 1; return true
      case "w": Rex.async(["block", "close", "-s", p.session, p.id], host: p.host); return true
      default: break
      }
    }
    if m == [.command, .shift], c == "r" { p.web.reloadFromOrigin(); return true }
    if m == [.command, .shift], c == "b" { openPane(beside: p, url: ""); return true }
    if m == [.control, .option] || m == [.control, .option, .function] || m == [.control, .option, .numericPad, .function] {
      let dir: String? = [123: "left", 124: "right", 125: "down", 126: "up"][Int(e.keyCode)]
      if let dir { returnToRex(p, focus: dir); return true }
    }
    if m == [.control, .option], c == "`" { returnToRex(p, focus: nil); return true }
    return false
  }

  func returnToRex(_ p: Panel, focus dir: String?) {
    p.focusedInRex = true
    activateRex()
    if let dir { Rex.async(["focus", "-s", p.session, "-b", p.id, dir], host: p.host) }
  }

  func activateRex() {
    _ = NSRunningApplication.runningApplications(withBundleIdentifier: "com.superlogical.rex").first?.activate()
      ?? NSWorkspace.shared.runningApplications.first { $0.localizedName?.hasPrefix("Rex") == true && $0.activationPolicy == .regular }?.activate()
  }

  func focus(_ p: Panel) {
    p.lastActive = Date()
    guard p.visible else { p.pendingFocus = true; return }
    NSApp.activate(ignoringOtherApps: true)
    p.window.makeKey()
    p.window.makeFirstResponder(p.web)
    if p.focusURLWhenShown { p.focusURLWhenShown = false; p.focusURL() }
  }

  func closePanel(_ id: String) {
    guard let p = panels.removeValue(forKey: id) else { return }
    p.close()
  }

  /// Open a browser pane beside `p`. A pane on another host runs `rexweb-remote hold` there, from that host's PATH.
  func openPane(beside p: Panel, url: String) {
    let pane = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/rexweb-pane").path
    let command = p.host == nil
      ? ["--label", "browser", "--shell=none", "--", "env", "REXWEB_FOCUS=true", pane, url]
      : ["--label", "rexweb", "--", "rexweb-remote", "hold", url]
    Rex.async(["split", "-s", p.session, "-b", p.id, "--split=right"] + command, host: p.host)
  }

  func add(id: String, session: String, host: String?, url: String) -> Panel {
    let p = Panel(id: id, session: session, host: host)
    panels[id] = p
    tracker.refresh(session)
    if !url.isEmpty { p.load(url) }
    log("pane \(id.suffix(6)) registered\(host.map { " on \($0)" } ?? "")")
    return p
  }

  /// Make a panel for a pane that `rexweb-remote hold` keeps, unless it has one.
  func adopt(_ m: Rex.Mark, host: String?) {
    guard panels[m.block] == nil else { return }
    add(id: m.block, session: m.session, host: host, url: m.url).reported = m.url
  }

  func resolve(_ raw: Any?) -> Panel? {
    let s = (raw as? String) ?? ""
    if s.isEmpty { return panels.values.max { $0.lastActive < $1.lastActive } }
    if let p = panels[s] { return p }
    let m = panels.values.filter { $0.id.hasSuffix(s) || $0.lastLabel.localizedCaseInsensitiveContains(s) }
    return m.count == 1 ? m[0] : nil
  }

  func js(_ p: Panel, _ body: String, _ args: [String: Any], _ done: @escaping (Any?, String?) -> Void) {
    p.web.callAsyncJavaScript(body, arguments: ["args": args], in: nil, in: .page) { r in
      switch r {
      case .success(let v): done(v, nil)
      case .failure(let e): done(nil, (e as NSError).userInfo["WKJavaScriptExceptionMessage"] as? String ?? e.localizedDescription)
      }
    }
  }

  func handle(path: String, input: [String: Any], reply: @escaping (Int, Any) -> Void) {
    let ok = { (v: Any) in reply(200, v) }
    let fail = { (s: String) in reply(400, ["error": s]) }
    let route = path.split(separator: "?").first.map(String.init) ?? path

    switch route {
    case "/health":
      let wins = Tracker.rexWindows().rex
      return ok([
        "ok": true, "pid": ProcessInfo.processInfo.processIdentifier, "panels": panels.count,
        "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
        "port": config.port, "rex_bin": config.rexBin, "rex_version": orNull(Rex.version),
        "rex_windows": wins.count,
        "window_names": wins.isEmpty ? NSNull() as Any : wins.contains { !$0.name.isEmpty } as Any,
        "config_error": orNull(config.configError),
      ])
    case "/list":
      return ok(["panels": panels.values.sorted { $0.lastActive > $1.lastActive }.map { $0.info() }])
    case "/register":
      guard let id = input["id"] as? String, let session = input["session"] as? String else { return fail("id and session required") }
      if let p = panels[id] { return ok(p.info()) }
      let url = input["url"] as? String ?? ""
      let p = add(id: id, session: session, host: nil, url: url)
      if input["focus"] as? Bool == true {
        p.focusURLWhenShown = url.isEmpty
        self.focus(p)
      }
      return ok(p.info())
    case "/close":
      guard let id = input["id"] as? String else { return fail("id required") }
      closePanel(id)
      return ok(["closed": id])
    case "/cookies":
      let list = input["cookies"] as? [[String: Any]] ?? []
      var n = 0
      let group = DispatchGroup()
      for item in list {
        var props: [HTTPCookiePropertyKey: Any] = [.name: item["name"] as? String ?? "", .value: item["value"] as? String ?? "",
                                                   .domain: item["domain"] as? String ?? "", .path: item["path"] as? String ?? "/"]
        if item["secure"] as? Bool == true { props[.secure] = "TRUE" }
        if let x = (item["expires"] as? NSNumber)?.doubleValue, x > 0 { props[.expires] = Date(timeIntervalSince1970: x) }
        if let c = HTTPCookie(properties: props) {
          group.enter(); n += 1
          Panel.store.httpCookieStore.setCookie(c) { group.leave() }
        }
      }
      group.notify(queue: .main) { ok(["set": n]) }
      return
    case "/links":
      let current = NSWorkspace.shared.urlForApplication(toOpen: URL(string: "https://example.com")!).flatMap { Bundle(url: $0)?.bundleIdentifier } ?? ""
      return ok(["default": current, "on": current == Links.selfID, "fallback": Links.fallbackID])
    case "/default-browser":
      let on = input["on"] as? Bool ?? true
      Links.makeDefault(on) { err in
        err == nil ? ok(["default": on ? Links.selfID : Links.fallbackID, "fallback": Links.fallbackID]) : fail(err!)
      }
      return
    case "/cookies/import":
      let domains = input["domains"] as? [String] ?? []
      let profile = input["profile"] as? String
      Rex.queue.async {
        do {
          let (cookies, skipped) = try ChromeCookies.read(profile: profile, domains: domains)
          DispatchQueue.main.async {
            let group = DispatchGroup()
            for c in cookies { group.enter(); Panel.store.httpCookieStore.setCookie(c) { group.leave() } }
            group.notify(queue: .main) {
              let reloadIDs = input["reload"] as? Bool == true ? self.panels.values.map { p in p.web.reload(); return p.id } : []
              ok(["imported": cookies.count, "skipped": skipped, "reloaded": reloadIDs])
            }
          }
        } catch {
          DispatchQueue.main.async { fail(error.localizedDescription) }
        }
      }
      return
    default: break
    }

    guard let p = resolve(input["id"]) else {
      return fail(panels.isEmpty ? "no browser panes; open one with `rexweb open URL`" : "no single pane matches \(input["id"] ?? "")")
    }
    if route != "/info" { p.lastActive = Date() }

    if ["/click", "/type", "/press"].contains(route), !p.visible {
      func retry(_ left: Int) {
        if p.visible { return handle(path: path, input: input, reply: reply) }
        if left == 0 {
          return fail("this pane isn't on screen, so it can't take clicks or typing. Show its Rex window and try again. eval, snapshot, and screenshot still work.")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { retry(left - 1) }
      }
      return retry(12)
    }
    switch route {
    case "/info":
      ok(p.info())
    case "/loaded":
      var replied = false
      let timeout = (input["timeout"] as? NSNumber)?.doubleValue ?? 30
      DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
        if !replied { replied = true; reply(408, ["error": "the page was still loading after \(Int(timeout))s", "url": p.web.url?.absoluteString ?? ""]) }
      }
      p.waitForLoad { err in
        guard !replied else { return }
        replied = true
        err == nil ? ok(p.info()) : reply(502, ["error": err!, "url": p.web.url?.absoluteString ?? ""])
      }
    case "/nav", "/open":
      guard let url = input["url"] as? String else { return fail("url required") }
      p.load(url) { err in
        let e = err ?? p.refusedError
        e == nil ? ok(p.info()) : reply(502, ["error": e!, "url": url])
      }
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
        if !p.web.isLoading, let e = p.refusedError { p.finishWaiters(e) }
      }
    case "/back": p.web.goBack(); p.waitForLoad { _ in ok(p.info()) }
    case "/forward": p.web.goForward(); p.waitForLoad { _ in ok(p.info()) }
    case "/reload": p.web.reload(); p.waitForLoad { _ in ok(p.info()) }
    case "/focus": focus(p); ok(p.info())
    case "/eval":
      let code = input["js"] as? String ?? ""
      js(p, JS.evaluate(code, asExpression: true), [:]) { v, e in
        guard let e else { return ok(["value": v ?? NSNull()]) }
        if !e.contains("SyntaxError") && !e.contains("Unexpected") { return fail(e) }
        self.js(p, JS.evaluate(code, asExpression: false), [:]) { v, e in e == nil ? ok(["value": v ?? NSNull()]) : fail(e!) }
      }
    case "/snapshot":
      let args: [String: Any] = ["max": input["max"] ?? 400, "textMax": input["text_max"] ?? 6000]
      func attempt(_ left: Int) {
        js(p, JS.snapshot, args) { v, e in
          if let e { return fail(e) }
          if v == nil || v is NSNull, left > 0 {
            return DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { attempt(left - 1) }
          }
          guard let v, !(v is NSNull) else { return fail("the page changed while it was read. Run snapshot again.") }
          ok(v)
        }
      }
      attempt(10)
    case "/click":
      js(p, JS.resolve, ["target": input["target"] as? String ?? ""]) { v, e in
        guard e == nil, let d = v as? [String: Any] else { return fail(e ?? "resolve failed") }
        if let err = d["error"] as? String { return fail(err) }
        let x = (d["x"] as? NSNumber)?.doubleValue ?? 0, y = (d["y"] as? NSNumber)?.doubleValue ?? 0
        self.nativeClick(p, x: x, y: y)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { p.waitForLoad { _ in ok(p.info()) } }
      }
    case "/type":
      js(p, JS.fill, ["target": input["target"] as? String ?? "", "text": input["text"] as? String ?? "",
                     "clear": input["clear"] as? Bool ?? false, "submit": input["submit"] as? Bool ?? false]) { v, e in
        guard e == nil else { return fail(e!) }
        if let d = v as? [String: Any], let err = d["error"] as? String { return fail(err) }
        if let d = v as? [String: Any], d["native"] as? Bool == true {
          p.window.makeFirstResponder(p.web)
          p.web.insertText(input["text"] as? String ?? "")
          if input["submit"] as? Bool == true { _ = self.nativeKey(p, "enter") }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { p.waitForLoad { _ in ok(p.info()) } }
      }
    case "/press":
      guard let k = input["key"] as? String else { return fail("key required") }
      if nativeKey(p, k) { ok(["pressed": k]) } else { fail("unknown key \(k)") }
    case "/shot":
      let path = (input["path"] as? String) ?? NSTemporaryDirectory() + "rexweb-\(p.id.suffix(6))-\(Int(Date().timeIntervalSince1970)).png"
      guard path.lowercased().hasSuffix(".png") else { return fail("screenshot path must end in .png") }
      p.web.takeSnapshot(with: nil) { img, err in
        guard let img, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else { return fail(err?.localizedDescription ?? "snapshot failed") }
        do { try png.write(to: URL(fileURLWithPath: path)); ok(["path": path, "width": rep.pixelsWide, "height": rep.pixelsHigh]) }
        catch { fail(error.localizedDescription) }
      }
    case "/wait":
      let deadline = Date().addingTimeInterval((input["timeout"] as? NSNumber)?.doubleValue ?? 15)
      let args: [String: Any] = ["selector": input["selector"] as? String ?? "", "text": input["text"] as? String ?? ""]
      func poll() {
        js(p, JS.exists, args) { v, _ in
          if v as? Bool == true { return ok(p.info()) }
          if Date() > deadline { return reply(408, ["error": "timed out"]) }
          DispatchQueue.main.asyncAfter(deadline: .now() + 0.1, execute: poll)
        }
      }
      p.waitForLoad { err in
        if let err { return reply(502, ["error": err, "url": p.web.url?.absoluteString ?? ""]) }
        poll()
      }
    default:
      reply(404, ["error": "unknown route \(route)"])
    }
  }

  func nativeClick(_ p: Panel, x: Double, y: Double) {
    let zoom = p.web.pageZoom * p.web.magnification
    let pt = p.web.convert(NSPoint(x: x * zoom, y: y * zoom), to: nil)
    let t = ProcessInfo.processInfo.systemUptime
    for (type, dt) in [(NSEvent.EventType.leftMouseDown, 0.0), (.leftMouseUp, 0.03)] {
      if let ev = NSEvent.mouseEvent(with: type, location: pt, modifierFlags: [], timestamp: t + dt,
                                     windowNumber: p.window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1) {
        p.window.sendEvent(ev)
      }
    }
  }

  func nativeKey(_ p: Panel, _ name: String) -> Bool {
    let keys: [String: (UInt16, String)] = [
      "enter": (36, "\r"), "return": (36, "\r"), "tab": (48, "\t"), "escape": (53, "\u{1b}"), "esc": (53, "\u{1b}"),
      "backspace": (51, "\u{7f}"), "delete": (117, "\u{f728}"), "space": (49, " "),
      "up": (126, "\u{f700}"), "down": (125, "\u{f701}"), "left": (123, "\u{f702}"), "right": (124, "\u{f703}"),
      "home": (115, "\u{f729}"), "end": (119, "\u{f72b}"), "pageup": (116, "\u{f72c}"), "pagedown": (121, "\u{f72d}"),
    ]
    guard let (code, chars) = keys[name.lowercased()] else { return false }
    if p.window.firstResponder == nil || p.window.firstResponder === p.window { p.window.makeFirstResponder(p.web) }
    let t = ProcessInfo.processInfo.systemUptime
    for type in [NSEvent.EventType.keyDown, .keyUp] {
      if let ev = NSEvent.keyEvent(with: type, location: .zero, modifierFlags: [], timestamp: t, windowNumber: p.window.windowNumber,
                                   context: nil, characters: chars, charactersIgnoringModifiers: chars, isARepeat: false, keyCode: code) {
        p.window.sendEvent(ev)
      }
    }
    return true
  }
}

let app = NSApplication.shared
app.delegate = App.shared
app.setActivationPolicy(.accessory)
app.run()
