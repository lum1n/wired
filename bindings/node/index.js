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

  /** The network's relays, as `{ url, pinned, owner }`. */
  relays() {
    return this._inner.relays()
  }

  /** The relay this node serves, as `{ url, localAddr }`, or null. */
  get servedRelay() {
    return this._inner.servedRelay ?? null
  }

  /** Root only: lists a relay (e.g. `https://robin.exe.xyz`) for the whole network. */
  addRelay(url) {
    return this._inner.addRelay(url)
  }

  /** Root only: stops listing a relay. */
  removeRelay(url) {
    return this._inner.removeRelay(url)
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

/** Paths a relay serves; iroh clients use them at the root of the relay's URL. */
const RELAY_PATHS = new Set(['/relay', '/ping'])

/**
 * Forwards a relay's traffic from your own HTTP server to the relay a node
 * serves behind it (`relayUrl` + `relayBind`). Use it where the platform gives
 * you one HTTPS port, like exe.dev:
 *
 *   const relay = relayProxy('127.0.0.1:8790')
 *   server.on('request', (req, res) => relay.matches(req) ? relay.request(req, res) : app(req, res))
 *   server.on('upgrade', (req, socket, head) => relay.matches(req) && relay.upgrade(req, socket, head))
 */
function relayProxy(localAddr) {
  const i = localAddr.lastIndexOf(':')
  const host = localAddr.slice(0, i).replace(/^\[|\]$/g, '')
  const port = Number(localAddr.slice(i + 1))
  return {
    matches(req) {
      return RELAY_PATHS.has((req.url || '').split('?')[0])
    },
    request(req, res) {
      const up = http.request({ host, port, method: req.method, path: req.url, headers: req.headers }, (r) => {
        res.writeHead(r.statusCode, r.headers)
        r.pipe(res)
      })
      up.on('error', () => {
        if (!res.headersSent) res.writeHead(502)
        res.end()
      })
      req.pipe(up)
    },
    upgrade(req, socket, head) {
      const up = net.connect(port, host, () => {
        const lines = [`${req.method} ${req.url} HTTP/1.1`]
        for (let j = 0; j < req.rawHeaders.length; j += 2) lines.push(`${req.rawHeaders[j]}: ${req.rawHeaders[j + 1]}`)
        up.write(lines.join('\r\n') + '\r\n\r\n')
        if (head && head.length) up.write(head)
        socket.pipe(up).pipe(socket)
      })
      const close = () => {
        socket.destroy()
        up.destroy()
      }
      up.on('error', close)
      socket.on('error', close)
      up.on('close', () => socket.destroy())
      socket.on('close', () => up.destroy())
    },
  }
}

/** `api.laptop.wired` -> `api@laptop`. */
function hostToTarget(host) {
  const m = /^([a-z0-9-]+)\.([a-z0-9-]+)\.wired\.?$/.exec(host || '')
  if (!m) throw new Error(`not a wired host: ${host} (want service.node.wired)`)
  return `${m[1]}@${m[2]}`
}

module.exports = { Node, WiredServer, relayProxy, hostToTarget }
