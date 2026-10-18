import Foundation
import Testing
@testable import Wired

private func localAnchor() async throws -> WiredNode {
    try await anchor(options: AnchorOptions(
        name: "vps", bindHost: "127.0.0.1", port: 0, qadPort: 0, publicHost: "127.0.0.1", ephemeral: true))
}

@Test func echoBetweenMembersWithHalfClose() async throws {
    let vps = try await localAnchor()
    let a = try await join(options: JoinOptions(name: "a", invite: vps.invite(), ephemeral: true))
    let b = try await join(options: JoinOptions(name: "b", invite: vps.invite(), ephemeral: true))

    let listener = try b.listen(service: "echo")
    let server = Task {
        for try await stream in listener.streams {
            let body = try await stream.readToEnd()
            try await stream.write("\(stream.peerName()):\(String(decoding: body, as: UTF8.self))")
            try await stream.finish()
        }
    }

    let s = try await a.dial(target: "echo@b")
    try await s.write("ping")
    try await s.finish()
    let reply = String(decoding: try await s.readToEnd(), as: UTF8.self)
    #expect(reply == "a:ping")

    await #expect(throws: WiredError.self) { try await a.dial(target: "nope@b") }

    listener.close()
    _ = try await server.value
    await a.close()
    await b.close()
    await vps.close()
}

@Test func anchorReachesMember() async throws {
    let vps = try await localAnchor()
    let laptop = try await join(options: JoinOptions(name: "laptop", invite: vps.invite(), ephemeral: true))
    let listener = try laptop.listen(service: "api")
    let server = Task {
        for try await stream in listener.streams {
            try await stream.write("hello \(stream.peerName())")
            try await stream.finish()
        }
    }
    let s = try await vps.dial(target: "api@laptop")
    try await s.finish()
    #expect(String(decoding: try await s.readToEnd(), as: UTF8.self) == "hello vps")
    listener.close()
    _ = try await server.value
    await laptop.close()
    await vps.close()
}

@Test func allowlistAndRevoke() async throws {
    let vps = try await localAnchor()
    let a = try await join(options: JoinOptions(name: "a", invite: vps.invite(), ephemeral: true))
    let b = try await join(options: JoinOptions(name: "b", invite: vps.invite(), ephemeral: true))
    let listener = try b.listen(service: "admin", allow: ["a"])
    let server = Task {
        for try await stream in listener.streams {
            try await stream.write("hi")
            try await stream.finish()
        }
    }

    let s = try await a.dial(target: "admin@b")
    try await s.finish()
    #expect(String(decoding: try await s.readToEnd(), as: UTF8.self) == "hi")
    await #expect(throws: WiredError.self) { try await vps.dial(target: "admin@b") }

    #expect(vps.isRoot() && !a.isRoot())
    #expect(throws: WiredError.self) { try a.revoke(name: "b") }
    let fresh = try vps.revoke(name: "a")
    #expect(fresh.hasPrefix("wired1"))
    #expect(!vps.members().contains { $0.name == "a" })
    await #expect(throws: WiredError.self) { try await a.dial(target: "admin@b") }

    listener.close()
    _ = try await server.value
    await a.close()
    await b.close()
    await vps.close()
}
