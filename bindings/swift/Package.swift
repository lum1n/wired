// swift-tools-version:5.9
import Foundation
import PackageDescription

let here = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
// Apple platforms: build WiredFFI.xcframework (scripts/xcframework.sh) and set WIRED_XCFRAMEWORK=1.
// Otherwise link lib/libwired_swift.a from scripts/build.sh.
let useXCFramework = ProcessInfo.processInfo.environment["WIRED_XCFRAMEWORK"] == "1"

let ffi: Target = useXCFramework
    ? .binaryTarget(name: "WiredFFI", path: "WiredFFI.xcframework")
    : .target(
        name: "WiredFFI",
        path: "Sources/WiredFFI",
        linkerSettings: [
            .unsafeFlags(["-L\(here)/lib"]),
            .linkedLibrary("wired_swift"),
            .linkedLibrary("m", .when(platforms: [.linux])),
            .linkedLibrary("dl", .when(platforms: [.linux])),
            .linkedFramework("Security", .when(platforms: [.macOS, .iOS])),
            .linkedFramework("SystemConfiguration", .when(platforms: [.macOS, .iOS])),
        ]
    )

let package = Package(
    name: "Wired",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "Wired", targets: ["Wired"])],
    targets: [
        ffi,
        .target(name: "Wired", dependencies: ["WiredFFI"], path: "Sources/Wired"),
        .executableTarget(name: "wired-echo", dependencies: ["Wired"], path: "Sources/WiredEcho"),
        .testTarget(name: "WiredTests", dependencies: ["Wired"], path: "Tests/WiredTests"),
    ]
)
