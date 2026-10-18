'use strict'

const net = require('node:net')
const http = require('node:http')
const { EventEmitter } = require('node:events')

const native = require(`./wired.${process.platform}-${process.arch}.node`)

/** Wraps a socket descriptor from the native side. */
function socketFromFd(fd, peer) {
  const socket = new net.Socket({ fd, readable: true, writable: true })
  socket.wiredPeer = peer
  return socket
}

/** Emits `connection` with a `net.Socket` for each incoming stream. */
class WiredServer extends EventEmitter {
  constructor(listener, service) {
    super()
    this.service = service
    this._listener = listener
    this._closed = false
    this._loop()
  }

  async _loop() {
    while (!this._closed) {
      let accepted
      try {
        accepted = await this._listener.accept()
      } catch (err) {
        this.emit('error', err)
        // Back off so a persistent failure (e.g. EMFILE) doesn't spin.
        await new Promise((r) => setTimeout(r, 100))
        continue
      }
      if (!accepted) break
      const peer = { name: accepted.peerName, id: accepted.peerId }
      this.emit('connection', socketFromFd(accepted.fd, peer))
    }
    this.emit('close')
  }

  close() {
    this._closed = true
    this._listener.close()
  }
}

class Node {
  constructor(inner) {
    this._inner = inner
  }

  /** Joins a network as a member. `invite` defaults to WIRED_INVITE. */
  static async join(opts) {
    return new Node(await native.join(opts))
  }

  /** Runs an anchor (on a publicly reachable host). */
  static async anchor(opts) {
    return new Node(await native.anchor(opts))
  }

  get name() {
    return this._inner.name
  }

  get id() {
    return this._inner.id
  }

  /** The network invite; on an anchor, hand this to other nodes. */
  get invite() {
    return this._inner.invite
  }

  get isAnchor() {
    return this._inner.isAnchor
  }

  /** The root anchor, where new nodes join and admin changes happen. */
  get isRoot() {
    return this._inner.isRoot
  }

  /** Every member, as `{ name, id, anchor }`. */
  members() {
    return this._inner.members()
  }

  /** Root only: removes `name` now; returns the new invite. */
  revoke(name) {
    return this._inner.revoke(name)
  }

  /** Root only: replaces the invite; returns the new one. */
  rotateInvite() {
    return this._inner.rotateInvite()
  }

  /** Root only: lets the replica anchor with this id join. */
  approveAnchor(id) {
    return this._inner.approveAnchor(id)
  }

  /** Opens a `net.Socket` to `service@node`. */
  async dial(target) {
    const fd = await this._inner.dial(target)
    return socketFromFd(fd, { name: target.split('@')[1] })
  }

  /**
   * Accepts streams for `service`; listen for `connection` events.
   * `options.allow`: node names that may connect (default: every member).
   */
  listen(service, options = {}) {
    return new WiredServer(this._inner.listen(service, options.allow), service)
  }

  /** Serves an `http.Server` (or anything handling `connection`) as `service`. */
  serve(service, server, options = {}) {
    const s = this.listen(service, options)
    s.on('connection', (socket) => server.emit('connection', socket))
    return s
  }

  /** Forwards streams for `service` to a local TCP address. */
  expose(service, target, options = {}) {
    return this._inner.expose(service, target, options.allow)
  }

  /** Listens on a local TCP address and forwards to `service@node`. */
  forward(local, target) {
    return this._inner.forward(local, target)
  }

  /** An http.Agent that routes `http://service.node.wired/` over Wired. */
  httpAgent(options) {
    const node = this
    const agent = new http.Agent({ keepAlive: true, ...options })
    agent.createConnection = (opts, cb) => {
      const target = hostToTarget(opts.host || opts.hostname)
      node.dial(target).then((s) => cb(null, s), cb)
    }
    return agent
  }

  /** 'direct', 'relay', or null when not connected to `node`. */
  path(node) {
    return this._inner.path(node)
  }

  close() {
    return this._inner.close()
  }
}

/** `api.laptop.wired` -> `api@laptop`. */
function hostToTarget(host) {
  const m = /^([a-z0-9-]+)\.([a-z0-9-]+)\.wired\.?$/.exec(host || '')
  if (!m) throw new Error(`not a wired host: ${host} (want service.node.wired)`)
  return `${m[1]}@${m[2]}`
}

module.exports = { Node, WiredServer }
