# Wired protocol, version 1

This document is normative for every Wired implementation and binding.

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

**Listing.** A relay gets into the network in one of two ways:
- The root adds it (`add_relay`). This is needed to bootstrap: a node can only join through a relay that the root is already connected to.
- A node that serves one announces it in `Join`, and the root records it with that node as `owner`. Revoking the owner removes its relays.

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

Every QUIC bidirectional stream starts with one `Open` frame from the side that opened it. The accepting side answers with one `Reply` frame. For `Watch`, the reply is a sequence of frames: one `State`, then `Delta`s.

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
5. If `relay` (a `RelayInfo`) is present, the root lists that relay with the joining key as its owner.

On success, the reply is `Reply::Joined { cert, anchor }`, where `anchor` is the answering anchor's own certificate. The joining node verifies both. Later `Join` streams on the same connection renew the certificate.

## Network state

```
Snapshot { version, members: name → key, denied: {key}, anchors: [AnchorInfo], relays: [RelayInfo], secret }
```

- The root owns the snapshot and increments `version` on every change.
- A node sends `Open::Watch` to an anchor. The anchor sends `Reply::State(snapshot)` immediately. After that, for as long as the stream stays open, it sends a `Reply::Delta` on every change:

  ```
  Delta { from, to, members_set: name → key, members_removed: {name},
          denied_added: {key}, denied_removed: {key},
          anchors: Option<[AnchorInfo]>, relays: Option<[RelayInfo]>, secret }
  ```

  - `from` is the version of the previous frame on the stream and `to` the new version. Several changes may arrive as one delta.
  - `members_set` holds the names that were added or whose key changed. `anchors` and `relays` are the full lists, sent only when they changed.
  - The watcher applies a delta to the state of the previous frame *on this stream*, which can be older than the state it holds. It then handles the result like a full snapshot. A delta whose `from` doesn't match is a protocol error: the watcher drops the session and reconnects.
- `secret` is sent only to anchors, so replicas can hand out current invites. Members receive `None`. Each frame carries the current value.
- Nodes ignore snapshots older than the one they have.
- Each member and replica keeps one Watch session open:
  - It starts attempts at anchors root first, 2 seconds apart, and keeps the first that succeeds.
  - When attached to a replica, it goes back to the root every 5 minutes.
  - It reconnects with backoff from 1 to 30 seconds.
- Names resolve locally from `members`. There is no lookup request.

## Peer connections

- The first stream between two nodes is `Open::Hello { cert }`. The acceptor checks the certificate and replies `Reply::Hello { cert }` with its own.
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
2. Publishes the change. Every watching node closes its connections to the key, and to peers whose certificate it issued, and refuses them from then on.

Existing members keep working. A registered key renews without a proof, so a member that was offline past its certificate rejoins with the old invite. The old invite can no longer add nodes, and the revoked node can't rejoin under any key.

Limits:
- A node that is cut off from every anchor learns of a revocation when it reconnects. Until then, the revoked node's certificate expires within 24 hours anyway.
- A member attached to a revoked replica learns of the revocation within 5 minutes, when it moves back to the root.

## Replicas

1. A replica starts with the network's invite. It is not trusted until an operator approves its key on the root (`wired approve <id>`).
2. The replica then sends `Join` with its `AnchorInfo` (and its `RelayInfo` if it serves one), receives an anchor certificate, and keeps a Watch session to replicate the snapshot.
3. If the root is down, existing members renew at replicas, peers keep verifying each other's certificates (chains end at the root key), and names keep resolving. Only new joins, revocations and approvals wait for the root.

### Losing the root

A replica can't become the root. Only the root holds the root key, and invites, certificates and every node's trust all name it. With the root key gone, nothing can issue anchor certificates. Replicas renew at the root once less than half their lifetime is left, so their certificates run out 15 to 30 days after the root's last renewal. Member certificates they issued stop verifying at the same time.

Recovery is one of these:
- **Restore the root's state directory.** The key (`<name>.key`) never changes. `anchor/state` does, and nodes apply a snapshot only if its `version` is higher than theirs. A root restored from a stale copy has a lower `version` than the network, so its updates are ignored until it has made as many changes as it missed.
- **Start a new network** with a new root key and `network_id`, and have every node join again with its invite. Nodes ignore cached state for another `network_id` or root.

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
