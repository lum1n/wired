'use strict'

const test = require('node:test')
const assert = require('node:assert')
const http = require('node:http')
const { Node } = require('..')

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
