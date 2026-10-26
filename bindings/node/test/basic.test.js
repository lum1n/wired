'use strict'

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const net = require('node:net')
const { Node, relayProxy } = require('..')

// A hang fails the test by name instead of stalling the run.
const T = { timeout: 30_000 }

const local = { bindHost: '127.0.0.1', port: 0, qadPort: 0, publicHost: '127.0.0.1', ephemeral: true }

/**
 * Closes `thing` when the test ends, passed or failed: a node, listener, task, agent or server
 * left open keeps the process alive, so a failing test would hang the run instead of failing it.
 */
function own(t, thing) {
  t.after(async () => {
    if (typeof thing.destroy === 'function' && thing instanceof http.Agent) thing.destroy()
    else if (thing instanceof http.Server) thing.close()
    else await thing.close()
  })
  return thing
}

function get(agent, url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, { agent }, (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (c) => (body += c))
        res.on('end', () => resolve({ status: res.statusCode, body }))
      })
      .on('error', reject)
  })
}

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

test('http over wired, anchor to member', T, async (t) => {
  const vps = own(t, await Node.anchor({ name: 'vps', ...local }))
  const laptop = own(t, await Node.join({ name: 'laptop', invite: vps.invite, ephemeral: true }))

  const server = http.createServer((req, res) => {
    res.end(`hello ${req.socket.wiredPeer.name} from ${laptop.name}${req.url}`)
  })
  own(t, laptop.serve('api', server))

  const agent = own(t, vps.httpAgent())
  const res = await get(agent, 'http://api.laptop.wired/x')
  assert.strictEqual(res.status, 200)
  assert.strictEqual(res.body, 'hello vps from laptop/x')

  // keep-alive reuses the socket
  const again = await get(agent, 'http://api.laptop.wired/y')
  assert.strictEqual(again.body, 'hello vps from laptop/y')
})

test('raw socket echo with half-close', T, async (t) => {
  const vps = own(t, await Node.anchor({ name: 'vps', ...local }))
  const a = own(t, await Node.join({ name: 'a', invite: vps.invite, ephemeral: true }))
  const b = own(t, await Node.join({ name: 'b', invite: vps.invite, ephemeral: true }))

  own(t, b.listen('echo')).on('connection', (s) => {
    const chunks = []
    s.on('data', (c) => chunks.push(c))
    s.on('end', () => s.end(`${s.wiredPeer.name}:${Buffer.concat(chunks)}`))
  })

  const s = await a.dial('echo@b')
  const got = await new Promise((resolve, reject) => {
    let out = ''
    s.setEncoding('utf8')
    s.on('data', (c) => (out += c))
    s.on('end', () => resolve(out))
    s.on('error', reject)
    s.end('ping')
  })
  assert.strictEqual(got, 'a:ping')

  await assert.rejects(a.dial('nope@b'), /NoSuchService/)
})

test('allowlist, admin calls and revoke', T, async (t) => {
  const vps = own(t, await Node.anchor({ name: 'vps', ...local }))
  const a = own(t, await Node.join({ name: 'a', invite: vps.invite, ephemeral: true }))
  const b = own(t, await Node.join({ name: 'b', invite: vps.invite, ephemeral: true }))

  own(t, b.listen('admin', { allow: ['a'] })).on('connection', (s) => {
    s.on('error', () => {}) // the caller hangs up at once
    s.end('hi')
  })
  own(t, b.listen('nobody', { allow: [] }))

  const s = await a.dial('admin@b')
  s.destroy()
  await assert.rejects(vps.dial('admin@b'), /Denied/)
  await assert.rejects(a.dial('nobody@b'), /Denied/)

  assert.strictEqual(vps.isRoot, true)
  assert.strictEqual(a.isRoot, false)
  assert.throws(() => a.revoke('b'), /only the root/)
  const fresh = vps.revoke('a')
  assert.match(fresh, /^wired1/)
  assert.ok(!vps.members().some((m) => m.name === 'a'))
  // The revocation reaches b within moments; from then on, a is refused.
  for (const deadline = Date.now() + 5000; b.members().some((m) => m.name === 'a'); ) {
    assert.ok(Date.now() < deadline, 'b never learned of the revocation')
    await new Promise((r) => setTimeout(r, 20))
  }
  await assert.rejects(a.dial('admin@b'))
})

test('root behind NAT, relay behind an app server on one port (exe.dev-style)', T, async (t) => {
  // home: the root on a laptop, no relay, unreachable directly.
  const home = own(
    t,
    await Node.anchor({ name: 'home', bindHost: '127.0.0.1', port: 0, noRelay: true, relayOnly: true, ephemeral: true }),
  )

  // robin: an app server on one port, like nudge behind exe.dev's proxy.
  const relayBind = `127.0.0.1:${await freePort()}`
  const relay = relayProxy(relayBind)
  const app = own(
    t,
    http.createServer((req, res) => (relay.matches(req) ? relay.request(req, res) : res.end('app'))),
  )
  app.on('upgrade', (req, socket, head) => (relay.matches(req) ? relay.upgrade(req, socket, head) : socket.destroy()))
  await new Promise((r) => app.listen(0, '127.0.0.1', r))
  const relayUrl = `http://127.0.0.1:${app.address().port}`

  home.addRelay(relayUrl)
  const robin = own(
    t,
    await Node.join({ name: 'robin', invite: home.invite, relayUrl, relayBind, relayOnly: true, ephemeral: true }),
  )
  assert.deepStrictEqual(robin.servedRelay, { url: relayUrl, localAddr: relayBind })

  // Both directions over HTTP, through robin's relay.
  own(t, home.serve('api', http.createServer((req, res) => res.end(`home says hi to ${req.socket.wiredPeer.name}`))))
  own(t, robin.serve('api', http.createServer((req, res) => res.end(`robin says hi to ${req.socket.wiredPeer.name}`))))
  const fromRobin = await get(own(t, robin.httpAgent()), 'http://api.home.wired/')
  assert.strictEqual(fromRobin.body, 'home says hi to robin')
  const fromHome = await get(own(t, home.httpAgent()), 'http://api.robin.wired/')
  assert.strictEqual(fromHome.body, 'robin says hi to home')
  assert.strictEqual(home.path('robin'), 'relay')

  // The app's own routes still work on the same port.
  const plain = await get(undefined, `${relayUrl}/`)
  assert.strictEqual(plain.body, 'app')
  assert.strictEqual(home.relays().length, 1)
})

test('expose and admin calls work from the JS thread', T, async (t) => {
  const vps = own(t, await Node.anchor({ name: 'vps', ...local }))
  const laptop = own(t, await Node.join({ name: 'laptop', invite: vps.invite, ephemeral: true }))
  const backend = own(t, http.createServer((req, res) => res.end('exposed')))
  await new Promise((r) => backend.listen(0, '127.0.0.1', r))
  own(t, laptop.expose('web', `127.0.0.1:${backend.address().port}`))
  const res = await get(own(t, vps.httpAgent()), 'http://web.laptop.wired/')
  assert.strictEqual(res.body, 'exposed')
  vps.addRelay('https://relay.example.com')
  assert.ok(vps.relays().some((r) => r.url === 'https://relay.example.com' && !r.pinned))
  vps.removeRelay('https://relay.example.com')
})
