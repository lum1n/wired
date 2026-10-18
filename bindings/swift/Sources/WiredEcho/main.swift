// Interop helper: `wired-echo serve <name>` | `wired-echo dial <name> <node>` (uses WIRED_INVITE).
import Foundation
import Wired

let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 2 else {
    print("usage: wired-echo serve <name> | dial <name> <node>")
    exit(2)
}
let node = try await join(options: JoinOptions(name: args[1], ephemeral: true))

if args[0] == "serve" {
    let listener = try node.listen(service: "echo")
    FileHandle.standardError.write(Data("serving echo@\(args[1])\n".utf8))
    for try await stream in listener.streams {
        Task {
            do {
                let body = try await stream.readToEnd()
                try await stream.write(data: body)
                try await stream.finish()
            } catch {
                FileHandle.standardError.write(Data("echo failed: \(error)\n".utf8))
            }
        }
    }
} else if args[0] == "dial", args.count == 3 {
    let s = try await node.dial(target: "echo@\(args[2])")
    try await s.write("ping")
    try await s.finish()
    let reply = String(decoding: try await s.readToEnd(), as: UTF8.self)
    guard reply == "ping" else {
        print("bad echo: \(reply)")
        exit(1)
    }
    print("roundtrip=ok")
    await node.close()
} else {
    print("usage: wired-echo serve <name> | dial <name> <node>")
    exit(2)
}
