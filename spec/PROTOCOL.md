# Wired protocol, version 2

This document is normative for every Wired implementation and binding.

`Join` and `Hello` carry the protocol version, 2. A node refuses any other version with `BadVersion`. Version 2 added the root's signature to snapshots, so every node in a network must run it. The ALPN, signature contexts and invite format still say `wired/1`; they did not change.

## Transport

- Every node is an iroh endpoint. Its identity is an Ed25519 key, and its endpoint id is the public key.
- Connections are QUIC with TLS 1.3, authenticated by raw public keys, using ALPN `wired/1`.
- NAT traversal (hole punching) and relay fallback are iroh's job. The only relays are the ones listed in the network state. No third-party relays or discovery services are used.

## Relays

- Relays are how nodes on different networks find each other, and what traffic falls back to when NAT traversal fails.
- They hold no keys and only ever see ciphertext.
- Any node can serve one. Nodes connect to every listed relay as needed.

A relay is listed as `RelayInfo { url, pin, qad_port, owner }`. There are two kinds:
- **Public:** on a reachable host. HTTPS uses a self-signed certificate made from the serving node's key. `pin` is that key, and clients accept the certificate only if it carries it. QUIC address discovery runs on `qad_port`.
- **Behind a proxy:** a TLS-terminating proxy (exe.dev, nginx, Caddy) forwards `/relay` (a WebSocket) and `/ping` at the root of `url` to the relay's plain-HTTP socket. `pin` is `None`, so clients check the certificate against the usual CA roots: Mozilla's, and the system's (which honor `SSL_CERT_FILE` and `SSL_CERT_DIR`). There is no address discovery.

**Access.** Relays admit a client only when both hold:
- it presents `Authorization: Bearer T`, where `T = hex(SHA-256("wired/1 relay-token" ‖ network_id)[..16])`;
- its key is not denied.

The token keeps strangers off the relay's bandwidth; it is not what protects traffic.

A relay closes any connection it hasn't admitted within 30 seconds, and lets at most 256 wait at once.

**Listing.** A relay gets into the network in one of two ways:
- The root adds it (`add_relay`). This is needed to bootstrap: a node can only join through a relay that the root is already connected to.
- A node that serves one announces it in `Join`, and the root records it with that node as `owner`. Revoking the owner removes its relays.

Relay URLs are origins (`https://host[:port]`, or `http://` for testing) of at most 256 bytes. A member lists at most one relay: a new announcement replaces its earlier one. It never replaces a listing another node owns. It may claim a listing the root added (owner `None`) when it announces no pin. A Public relay's `pin` must be the announcing node's key. Nodes skip any listed relay they cannot use, and still start.

## Roles

- **Root anchor.** It creates the network. Its key is the trust anchor, and it is the only place where the network's state can change: new keys, revocations, anchor approvals and relays. It needs no inbound reachability: it can sit behind NAT and reach everyone through relays.
- **Replica anchors.** They are approved by the root. They renew certificates for keys the network already knows, and push the network state to members.
- **Members.** Every other node.

## Network and invite

- A network has:
  - a random 16-byte `network_id`, fixed for its lifetime
  - the root's key
  - a 32-byte join secret `S`, which is rotated on revocation
- An invite string is `wired1` followed by lowercase RFC 4648 base32, without padding, of:

  ```
  postcard(Invite { version: 1, network_id, root, secret: S,
                    anchors: [AnchorInfo { id, addrs }], relays: [RelayInfo { url, pin, qad_port, owner }] })
  ‖ SHA-256(payload)[..4]
  ```

- The invite is a credential: anyone who holds it can add a new node until `S` is rotated. It is not needed again once a key has joined.

## Framing

All control messages are frames: a u32 big-endian length (at most 1 MiB) followed by the postcard encoding of the message. See `crates/wired-core/src/proto.rs`.

Every QUIC bidirectional stream starts with one `Open` frame from the side that opened it. The accepting side answers with one `Reply` frame. For `Watch`, the reply is a sequence of frames.

## Certificates

```
cert.body        = { network_id, node_id, name, role: Member | Anchor, expires, issuer }
cert.sig         = Ed25519_sign(issuer_key, "wired/1 cert" ‖ postcard(cert.body))
cert.issuer_cert = the issuer's anchor certificate, if the issuer is not the root
```

- The root issues anchor certificates (valid 30 days) and member certificates (valid 24 hours). Replicas issue member certificates only.
- Holders renew once less than half the lifetime is left.

A certificate presented on a connection is valid when all of these hold:
1. `node_id` is the connection's remote key.
2. `network_id` matches.
3. `expires` is in the future.
4. Neither `node_id` nor `issuer` is in the network's `denied` set.
5. The signature checks out:
   - If `issuer` is the root, `sig` verifies under the root key.
   - Otherwise `issuer_cert` must:
     - belong to `issuer`
     - have role `Anchor`
     - be issued by the root and verify under the root key
     - itself pass checks 2–4

     and then `sig` must verify under `issuer`.

## Joining and renewal

The first stream a node opens to an anchor is `Open::Join { version, network_id, name, proof, anchor, relay }`, where:

```
proof = HMAC-SHA256(S, "wired/1 join-proof" ‖ node_id ‖ E)
E     = TLS exporter of the QUIC connection, label "wired/1 join", empty context, 32 bytes
```

The anchor checks, in order:
1. The version and the `network_id`.
2. The key is not denied.
3. Whether the key is already registered:
   - **Registered key.** `name` must equal its registered name. No proof is needed: the TLS handshake proved possession of the key. Any anchor may renew it.
   - **New key.** It is accepted only at the root. `proof` must verify under the current `S`, compared in constant time, and `name` must be unclaimed. The root records the name and the key atomically.
4. If `anchor` (an `AnchorInfo`) is present, the key must have been approved on the root. The root then records the key as an anchor and issues an anchor certificate.
5. If `relay` (a `RelayInfo`) is present, it must be valid (see Listing) or the join is refused. The root lists that relay with the joining key as its owner.

On success, the reply is `Reply::Joined { cert, anchor }`, where `anchor` is the answering anchor's own certificate. The joining node verifies both. Later `Join` streams on the same connection renew the certificate.

## Network state

```
Snapshot { version, members: name → key, denied: {key}, anchors: [AnchorInfo], relays: [RelayInfo], secret, sig }
sig = Ed25519_sign(root_key, "wired/1 snapshot" ‖ postcard(snapshot with secret = None, sig = []))
```

- The root owns the snapshot. On every change it sets `version = max(version + 1, now in Unix milliseconds)` and signs it. Versions never go back, even when the root restarts from older saved state.
- Other anchors pass the snapshot on unchanged. They can't alter it.
- A node sends `Open::Watch` to an anchor. The anchor sends `Reply::State(snapshot)` immediately, and again on every change, for as long as the stream stays open.
- `secret` is sent only to anchors, so replicas can hand out current invites. Members receive `None`.
- A node takes a snapshot only if `sig` verifies under the root key and `version` is higher than the one it has. Anything else is ignored.
- Each member and replica keeps one Watch session open:
  - It starts attempts at anchors root first, 2 seconds apart, and keeps the first that succeeds.
  - When attached to a replica, it goes back to the root every 5 minutes.
  - It reconnects with backoff from 1 to 30 seconds.
- Names resolve locally from `members`. There is no lookup request.
- A root that starts from saved state first asks the other anchors (`Watch`, waiting at most 5 seconds) for their snapshot. If one it signed is newer than its own, it continues from that one, so revocations made after a backup survive a restore.

## Peer connections

- The first stream between two nodes is `Open::Hello { version, cert }`. The acceptor checks the certificate and replies `Reply::Hello { cert }` with its own.
- Both sides also check that `members` maps the certificate's name to the peer's key, waiting up to 2 seconds for a node that just joined. Otherwise the acceptor refuses with `Unauthorized`. So an anchor can't certify a name for another key.
- Both sides must reject any other stream on the connection until this exchange has finished.
- The dialer must check that the peer's certificate carries the name it dialed.

## Services

- `Open::Service { name }` asks for a byte stream to a service on the peer.
- The peer replies `ServiceOk` and the raw byte stream follows, or it replies `Error` and closes the stream.
- A service may have an allowlist of node names. A peer that isn't on it gets `Denied`. Names are bound to keys by certificates and are unique in the network.
- Services are addressed as `service@node`.

## Revocation

Revoking a node on the root does the following:
1. Removes its name, adds its key to `denied`, removes it from `anchors` and any relays it owns, and rotates `S`.
2. Publishes the new snapshot. Every watching node closes its connections to the key, and to peers whose certificate it issued, and refuses them from then on.

Existing members keep working. The old invite can no longer add nodes, and the revoked node can't rejoin under any key.

Limits:
- A node that is cut off from every anchor learns of a revocation when it reconnects. Until then, the revoked node's certificate expires within 24 hours anyway.
- A member attached to a revoked replica learns of the revocation within 5 minutes, when it moves back to the root.

## Replicas

1. A replica starts with the network's invite. It is not trusted until an operator approves its key on the root (`wired approve <id>`).
2. The replica then sends `Join` with its `AnchorInfo` (and its `RelayInfo` if it serves one), receives an anchor certificate, and keeps a Watch session to replicate the snapshot.
3. If the root is down, existing members renew at replicas, peers keep verifying each other's certificates (chains end at the root key), and names keep resolving. Only new joins, revocations and approvals wait for the root.

## Errors

| Code | Meaning |
|------|---------|
| `BadVersion` | Unsupported protocol version |
| `WrongNetwork` | `network_id` doesn't match |
| `Unauthorized` | Bad proof or bad certificate |
| `NameTaken` | The name belongs to another key |
| `NotPrimary` | A new key must join at the root |
| `NotApproved` | The replica hasn't been approved on the root |
| `NoSuchService` | No service with that name |
| `Denied` | Revoked key, or not on the service's allowlist |
| `Protocol` | Malformed or unexpected message |

`BadVersion`, `WrongNetwork`, `Unauthorized`, `NameTaken` and `Denied` are fatal: retrying won't help without operator action.

## Administration

A running anchor listens on a Unix socket at `<state_dir>/anchor/admin.sock`. The socket has mode 0600 and sits in a 0700 directory.
- **Request:** one line, one of `invite`, `rotate`, `revoke <name>`, `approve <id>`, `members`, `relays`, `relay add <url>` or `relay remove <url>`.
- **Response:** `ok` followed by the output, or `error: <message>`.
