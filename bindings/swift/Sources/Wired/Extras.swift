import Foundation

extension WiredListener {
    /// Incoming streams as an async sequence; ends when the listener or node closes.
    public var streams: AsyncThrowingStream<WiredStream, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    while let stream = try await self.accept() {
                        continuation.yield(stream)
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

extension WiredStream {
    /// Reads until the peer finishes its side.
    public func readToEnd(chunk: UInt32 = 64 * 1024) async throws -> Data {
        var out = Data()
        while let part = try await read(max: chunk) {
            out.append(part)
        }
        return out
    }

    public func write(_ string: String) async throws {
        try await write(data: Data(string.utf8))
    }
}
