// Interop helper: `node echo.js serve <name>` | `node echo.js dial <name> <node>` (uses WIRED_INVITE).
'use strict'
const { Node } = require('..')

async function main() {
  const [cmd, name, peer] = process.argv.slice(2)
  const node = await Node.join({ name, ephemeral: true })
  if (cmd === 'serve') {
    node.listen('echo').on('connection', (s) => {
      const chunks = []
      s.on('data', (c) => chunks.push(c))
      s.on('end', () => s.end(Buffer.concat(chunks)))
    })
    console.error(`serving echo@${name}`)
    return
  }
  const s = await node.dial(`echo@${peer}`)
  const got = await new Promise((resolve, reject) => {
    const chunks = []
    s.on('data', (c) => chunks.push(c))
    s.on('end', () => resolve(Buffer.concat(chunks).toString()))
    s.on('error', reject)
    s.end('ping')
  })
  if (got !== 'ping') {
    console.log(`bad echo: ${got}`)
    process.exit(1)
  }
  console.log('roundtrip=ok')
  await node.close()
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
