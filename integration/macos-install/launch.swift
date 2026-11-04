// Only launches the exact test bundle through LaunchServices, observes its
// window metadata, and requests normal termination. No screenshots, accessibility
// permissions, AppleScript, forced quit, or VPN operations.
import AppKit
import CoreGraphics
import Foundation

func finish(_ code: Int32, _ result: String) -> Never {
    print(result)
    exit(code)
}
guard CommandLine.arguments.count == 3 else { finish(2, "参数错误") }
let url = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
let configPath = CommandLine.arguments[2]
guard url.lastPathComponent == "Meridian Preview.app",
      !FileManager.default.fileExists(atPath: configPath),
      NSRunningApplication.runningApplications(withBundleIdentifier: "site.meridian-vpn.preview").isEmpty
else { finish(2, "已有应用或配置，拒绝启动") }
let config = NSWorkspace.OpenConfiguration()
config.arguments = ["--config", configPath]
config.createsNewApplicationInstance = true
config.activates = true
var application: NSRunningApplication?
var launchError = false
var completed = false
NSWorkspace.shared.openApplication(at: url, configuration: config) { app, error in
    DispatchQueue.main.async {
        application = app
        launchError = error != nil
        completed = true
    }
}
let deadline = Date().addingTimeInterval(30)
var observed = false
var ownedPID: pid_t = -1
while Date() < deadline {
    RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    if completed && (launchError || application == nil) { finish(3, "系统拒绝启动应用；未绕过安全限制") }
    if let app = application {
        guard app.bundleURL?.standardizedFileURL == url, app.executableURL?.standardizedFileURL == url.appendingPathComponent("Contents/MacOS/meridian"), !app.isTerminated else { finish(4, "应用身份不匹配或提前退出") }
        if ownedPID == -1 { ownedPID = app.processIdentifier }
        guard ownedPID > 0, app.processIdentifier == ownedPID else { finish(11, "应用进程标识无效") }
        // No title/image is requested. PID, bounds and layer are non-image metadata.
        let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
        observed = windows.contains { item in
            guard (item[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == ownedPID,
                  (item[kCGWindowLayer as String] as? NSNumber)?.intValue == 0,
                  let bounds = item[kCGWindowBounds as String] as? [String: Any],
                  let width = bounds["Width"] as? NSNumber, let height = bounds["Height"] as? NSNumber else { return false }
            return width.doubleValue >= 400 && height.doubleValue >= 250
        }
        if observed { break }
    }
}
guard let app = application else { finish(5, "启动超时；不得据此认定成功") }
// Leave a bounded observation interval for the external read-only sampler.
if observed {
    let observationDeadline = Date().addingTimeInterval(5)
    while Date() < observationDeadline {
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        if app.isTerminated { finish(9, "观察期间应用意外退出") }
    }
}
// Ask normally even if window verification failed. Never force termination.
guard app.terminate() else { finish(6, "正常退出请求被拒绝；保留现场") }
let quitDeadline = Date().addingTimeInterval(30)
while !app.isTerminated && Date() < quitDeadline {
    RunLoop.current.run(until: Date().addingTimeInterval(0.1))
}
guard app.isTerminated else { finish(7, "正常退出超时；未强制终止") }
guard ownedPID > 0, let remaining = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] else { finish(12, "退出后的窗口观察不可用") }
if remaining.contains(where: { ($0[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == ownedPID }) {
    finish(10, "退出后仍观察到原应用窗口")
}
guard observed else { finish(8, "未观察到有效应用窗口") }
finish(0, "窗口已观察，正常退出已请求且已观察到进程终止")
