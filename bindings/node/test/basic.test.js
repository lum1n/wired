'use strict'

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const net = require('node:net')
const { Node, relayProxy } = require('..')

const local = { bindHost: '127.0.0.1', port: 0, qadPort: 0, publicHost: '127.0.0.1', ephemeral: true }

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

test('http over wired, anchor to member', async () => {
  const vps = await Node.anchor({ name: 'vps', ...local })
  const laptop = await Node.join({ name: 'laptop', invite: vps.invite, ephemeral: true })

  const server = http.createServer((req, res) => {
    res.end(`hello ${req.socket.wiredPeer.name} from ${laptop.name}${req.url}`)
  })
  const ln = laptop.serve('api', server)

  const agent = vps.httpAgent()
  const res = await get(agent, 'http://api.laptop.wired/x')
  assert.strictEqual(res.status, 200)
  assert.strictEqual(res.body, 'hello vps from laptop/x')

  // keep-alive reuses the socket
  const again = await get(agent, 'http://api.laptop.wired/y')
  assert.strictEqual(again.body, 'hello vps from laptop/y')

  agent.destroy()
  ln.close()
  await laptop.close()
  await vps.close()
})

test('raw socket echo with half-close', async () => {
  const vps = await Node.anchor({ name: 'vps', ...local })
  const a = await Node.join({ name: 'a', invite: vps.invite, ephemeral: true })
  const b = await Node.join({ name: 'b', invite: vps.invite, ephemeral: true })

  const ln = b.listen('echo')
  ln.on('connection', (s) => {
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

  ln.close()
  await Promise.all([a.close(), b.close()])
  await vps.close()
})

test('allowlist, admin calls and revoke', async () => {
  const vps = await Node.anchor({ name: 'vps', ...local })
  const a = await Node.join({ name: 'a', invite: vps.invite, ephemeral: true })
  const b = await Node.join({ name: 'b', invite: vps.invite, ephemeral: true })

  const ln = b.listen('admin', { allow: ['a'] })
  ln.on('connection', (s) => s.end('hi'))
  const nobody = b.listen('nobody', { allow: [] })

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
  await assert.rejects(a.dial('admin@b'))

  ln.close()
  nobody.close()
  await Promise.all([a.close(), b.close()])
  await vps.close()
})

function freePort() {
  return new Promise((resolve) => {
    const srv = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

test('root behind NAT, relay behind an app server on one port (exe.dev-style)', async () => {
  // home: the root on a laptop, no relay, unreachable directly.
  const home = await Node.anchor({ name: 'home', bindHost: '127.0.0.1', port: 0, noRelay: true, relayOnly: true, ephemeral: true })

  // robin: an app server on one port, like nudge behind exe.dev's proxy.
  const relayBind = `127.0.0.1:${await freePort()}`
  const relay = relayProxy(relayBind)
  const app = http.createServer((req, res) => (relay.matches(req) ? relay.request(req, res) : res.end('app')))
  app.on('upgrade', (req, socket, head) => (relay.matches(req) ? relay.upgrade(req, socket, head) : socket.destroy()))
  await new Promise((r) => app.listen(0, '127.0.0.1', r))
  const relayUrl = `http://127.0.0.1:${app.address().port}`

  home.addRelay(relayUrl)
  const robin = await Node.join({ name: 'robin', invite: home.invite, relayUrl, relayBind, relayOnly: true, ephemeral: true })
  assert.deepStrictEqual(robin.servedRelay, { url: relayUrl, localAddr: relayBind })

  // Both directions over HTTP, through robin's relay.
  const homeApi = home.serve('api', http.createServer((req, res) => res.end(`home says hi to ${req.socket.wiredPeer.name}`)))
  const robinApi = robin.serve('api', http.createServer((req, res) => res.end(`robin says hi to ${req.socket.wiredPeer.name}`)))
  const fromRobin = await get(robin.httpAgent(), 'http://api.home.wired/')
  assert.strictEqual(fromRobin.body, 'home says hi to robin')
  const fromHome = await get(home.httpAgent(), 'http://api.robin.wired/')
  assert.strictEqual(fromHome.body, 'robin says hi to home')
  assert.strictEqual(home.path('robin'), 'relay')

  // The app's own routes still work on the same port.
  const plain = await get(undefined, `${relayUrl}/`)
  assert.strictEqual(plain.body, 'app')
  assert.strictEqual(home.relays().length, 1)

  homeApi.close()
  robinApi.close()
  await robin.close()
  await home.close()
  app.close()
})

test('expose and admin calls work from the JS thread', async () => {
  const vps = await Node.anchor({ name: 'vps', ...local })
  const laptop = await Node.join({ name: 'laptop', invite: vps.invite, ephemeral: true })
  const backend = http.createServer((req, res) => res.end('exposed'))
  await new Promise((r) => backend.listen(0, '127.0.0.1', r))
  const task = laptop.expose('web', `127.0.0.1:${backend.address().port}`)
  const res = await get(vps.httpAgent(), 'http://web.laptop.wired/')
  assert.strictEqual(res.body, 'exposed')
  vps.addRelay('https://relay.example.com')
  assert.ok(vps.relays().some((r) => r.url === 'https://relay.example.com' && !r.pinned))
  vps.removeRelay('https://relay.example.com')
  task.close()
  backend.close()
  await laptop.close()
  await vps.close()
})
