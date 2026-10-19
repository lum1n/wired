# wired

Wired is an embeddable library that lets services talk to each other over an encrypted network. Setup is one invite string.

- **Encrypted and authenticated.** Traffic uses QUIC with TLS 1.3. Every node is an Ed25519 key, and there is no CA.
- **Works behind NAT.** Nodes punch through NATs to connect directly. When that fails, traffic falls back to a relay, which only ever sees ciphertext.
- **Self-hosted.** Membership and name lookup run inside the library on the *anchor*, which can sit behind NAT. Relays (for finding each other across networks) run inside the library too, on any reachable node, even behind an HTTPS proxy like exe.dev's. There are no third-party servers.
- **Named services.** Services are addressed as `service@node`, for example `api@laptop`.

Built on [iroh](https://iroh.computer), with all of n0's default infrastructure turned off.

## Install

Each [release](https://github.com/lum1n/wired/releases) has, for Linux x64/arm64 and macOS arm64:
- `wired-<version>-<platform>.tar.gz`: the `wired` CLI.
- `wired-node-<version>-<platform>.tar.gz`: the Node binding, ready to `require('./wired-node')`.

`SHA256SUMS` lists their hashes. Linux builds need glibc 2.35 or newer (Debian 12, Ubuntu 22.04). To build from source: `cargo build --release -p wired-cli`.

## The 60-second version

On a VPS with a public IP, start the anchor (it serves a relay too) and forward a local port to the laptop's service:

```sh
wired anchor --name vps --forward 127.0.0.1:9000=api@laptop   # prints an invite: wired1…
```

On your laptop (behind NAT, nothing open inbound), expose a local HTTP server:

```sh
export WIRED_INVITE=wired1…
wired join --name laptop --expose api=127.0.0.1:8080
```

Back on the VPS:

```sh
curl http://127.0.0.1:9000/
```

Want only the VPS to reach it? Add `--allow api=vps`.

The anchor needs **UDP 7443** (peers), **TCP 7443** (relay) and **UDP 7842** (address discovery) open. If the VPS's public IP isn't on its network interface (common on AWS and GCP), pass `--public-host <ip-or-dns>`.

## Embedding (Rust)

```rust
// Public host: anchor plus a relay
let vps = wired::Node::builder("vps").anchor(Default::default()).relay(wired::RelayServe::public()).spawn().await?;
println!("{}", vps.invite());

// Anywhere else (reads WIRED_INVITE, or use .invite(...))
let laptop = wired::Node::builder("laptop").spawn().await?;
let mut ln = laptop.listen("api")?;
while let Some(stream) = ln.accept().await {
    // stream: AsyncRead + AsyncWrite; stream.peer() says who is calling
}

// Dial from any member
let stream = vps.dial("api@laptop").await?;
```

`expose(service, "127.0.0.1:8080")` and `forward("127.0.0.1:9000", "api@laptop")` bridge to plain TCP, so existing services work without code changes.

## Other languages

Every binding wraps the same Rust core. On Unix, the Node and Go bindings get each stream as a socket descriptor, so you get native socket types. Swift gets async read/write instead.

**Go** (`bindings/go`, cgo; run `scripts/build.sh` first). A `Listener` is a `net.Listener` and a `Conn` is a `net.Conn`.

```go
laptop, _ := wired.Join(wired.JoinOptions{Name: "laptop"})
ln, _ := laptop.Listen("api")
go http.Serve(ln, handler)

resp, _ := vps.HTTPClient().Get("http://api.laptop.wired/")
```

**Node** (`bindings/node`, napi-rs; run `npm run build` first). Streams are `net.Socket`s.

```js
const { Node } = require('@wired/node')
const laptop = await Node.join({ name: 'laptop' })
laptop.serve('api', http.createServer(handler))

http.get('http://api.laptop.wired/', { agent: vps.httpAgent() }, onResponse)
```

**Swift** (`bindings/swift`, UniFFI; run `scripts/build.sh` on Linux, or `scripts/xcframework.sh` on macOS for iOS/macOS).

```swift
let laptop = try await join(options: JoinOptions(name: "laptop"))
for try await stream in try laptop.listen(service: "api").streams {
    let request = try await stream.readToEnd()
    try await stream.write("hi \(stream.peerName())")
    try await stream.finish()
}
```

## Anchor behind NAT, relays elsewhere

The anchor doesn't have to be reachable. Run it on your laptop without a relay, and let reachable nodes serve relays, even behind a TLS-terminating proxy that gives you one HTTPS port, like exe.dev:

```sh
# laptop (root, behind NAT)
wired anchor --name home --no-relay

# tell the network about the VM's relay before the VM joins through it
wired relay add https://robin.exe.xyz

# robin (exe.dev VM): its proxy forwards /relay and /ping to 127.0.0.1:8790
wired join --name robin --relay-url https://robin.exe.xyz --relay-bind 127.0.0.1:8790
```

If your app already owns the HTTPS port, forward just those two paths. In Node: `relayProxy('127.0.0.1:8790')` gives `matches`, `request` and `upgrade` handlers for an `http.Server`.

`wired status` shows whether a node is connected to its home relay, the relay others reach it through, and why not if it isn't.

The relay admits only this network's nodes (it checks a token derived from the network, and refuses revoked keys). It only ever sees ciphertext.

## Access control

- Restrict a service to named nodes with `--allow api=vps,desktop` on the CLI, or `listen_allow` / `expose_allow` in the library. Names are bound to keys by certificates and are unique in the network.
- `wired members` lists the network's nodes.
- `wired revoke <name>` removes a node now. Every node drops its connections to it within moments. The join secret rotates, so the command prints a new invite; existing members are unaffected, and the revoked node can't rejoin under any key.
- `wired rotate` replaces a leaked invite without revoking anyone.

Admin commands talk to the running anchor through a local socket in its state directory, so only the user running the anchor can use them.

## More than one anchor

The first anchor is the **root**. Its key is the network's trust anchor. Add replicas on other hosts for redundancy:

```sh
# vps2
wired anchor --name vps2 --replica-of wired1…    # prints its id
# vps (root)
wired approve <vps2-id>
```

- Replicas serve a relay, renew certificates and push updates.
- Invites issued after a replica joins list it, and members learn about it automatically.
- If the root is down, the network keeps running: members renew at a replica and peers still verify each other. Only new joins, revocations and approvals wait for the root.
- Back up the root's state directory (`~/.config/wired`). It holds the network's root key.

## Security model

- The **invite is a credential**: it can add new nodes until the secret is rotated. Treat it like a password.
- A new key joins by proving it knows the secret with an HMAC bound to the TLS session. The secret itself never goes over the wire. After that, the key itself is the identity.
- Anchors give members 24-hour certificates that bind a name to a key. Certificates chain to the root key, and every node checks them before opening any service stream.
- Revocations reach every connected node at once. A node cut off from all anchors catches up when it reconnects. Even then, a revoked node's certificate expires within 24 hours.
- Members cache their certificate and the network state, so they start even when no anchor is reachable, until that certificate expires.
- Keys and state live in `$XDG_CONFIG_HOME/wired` (mode 0600/0700).

See [`spec/PROTOCOL.md`](spec/PROTOCOL.md) for the wire protocol.

## Layout

| Path | What |
|------|------|
| `crates/wired-core` | protocol, anchor, node runtime |
| `crates/wired` | public Rust API |
| `crates/wired-cli` | the `wired` binary |
| `crates/wired-ffi` | C ABI used by the Go binding |
| `bindings/{go,node,swift}` | language bindings |
| `spec/PROTOCOL.md` | wire protocol |
| `tests/interop/` | NAT scenario and cross-language matrix |

## Testing

```sh
cargo test --workspace          # unit tests + in-process networks (direct and relay-only)
tests/interop/nat.sh            # rootless netns: hole punching through NAT, relay fallback with UDP blocked
tests/interop/matrix.sh         # echo between Rust, Go, Node and Swift, every pair
(cd bindings/go && go test ./...)
(cd bindings/node && npm test)
(cd bindings/swift && swift test)
```

## License

MIT. See [LICENSE](LICENSE).
