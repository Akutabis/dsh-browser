import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import test from 'node:test'
import { isLocalDshGrant, localDshGrant, localDshHeaders } from '../lib/browser-electron/local-dsh-auth.js'

const cookie = 'dsh_test_only=fixture.signature'
const attrs = `${cookie}; Max-Age=600; Path=/; HttpOnly; SameSite=Strict`
const launch = base => `${base}?token=fixture`

async function fixture(t) {
  let mode = 'ok'
  const seen = []
  const server = createServer((req, res) => {
    seen.push(req.url)
    res.writeHead(303, { location: mode === 'ok' ? './' : '/other', 'set-cookie': attrs })
    res.end()
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise(resolve => server.close(resolve)))
  const origin = `http://127.0.0.1:${server.address().port}`
  return { origin, root: `${origin}/`, seen, setMode(next) { mode = next } }
}

test('uses the exact live loopback root and never follows the launch redirect', async t => {
  const { origin, root, seen } = await fixture(t)
  assert.equal(await localDshGrant(`${root}other`, () => origin, launch), undefined)
  assert.equal(await localDshGrant(root, () => 'http://127.0.0.1:1', launch), undefined)
  assert.deepEqual(seen, [])
  const grant = await localDshGrant(root, () => origin, launch)
  assert.equal(grant.origin, origin)
  assert.equal(grant.cookie, cookie)
  assert.ok(isLocalDshGrant(grant))
  assert.deepEqual(seen, ['/?token=fixture'])
})

test('rejects an altered launch origin and unexpected redirect with a generic error', async t => {
  const { origin, root, seen, setMode } = await fixture(t)
  await assert.rejects(localDshGrant(root, () => origin, () => 'http://127.0.0.1:1/?token=fixture'), /^Error: browser: local DSH sign-in failed$/)
  assert.deepEqual(seen, [])
  setMode('bad')
  await assert.rejects(localDshGrant(root, () => origin, launch), /^Error: browser: local DSH sign-in failed$/)
  assert.deepEqual(seen, ['/?token=fixture'])
})

test('confines credential use to this view’s DSH origin and same-origin requests', () => {
  const origin = 'http://127.0.0.1:55557'
  const grant = { origin, cookie, expiresAt: Date.now() + 1_000 }
  assert.equal(localDshHeaders(grant, `${origin}/`, 'mainFrame', { 'Sec-Fetch-Site': 'none' }).Cookie, cookie)
  assert.equal(localDshHeaders(grant, `${origin}/api`, 'xhr', { 'Sec-Fetch-Site': 'same-origin', Cookie: 'other=ok; dsh_test_only=old' }).Cookie, `other=ok; ${cookie}`)
  assert.equal(localDshHeaders(grant, 'ws://127.0.0.1:55557/api/remote.mux', 'webSocket', { Origin: origin }).Cookie, cookie)
  assert.equal(localDshHeaders(grant, 'http://127.0.0.1:55558/', 'mainFrame', { 'Sec-Fetch-Site': 'none' }).Cookie, undefined)
  assert.equal(localDshHeaders(grant, `${origin}/`, 'mainFrame', { 'Sec-Fetch-Site': 'same-site' }).Cookie, undefined)
  assert.equal(localDshHeaders(grant, 'ws://127.0.0.1:55557/api/remote.mux', 'webSocket', { Origin: 'http://127.0.0.1:55558' }).Cookie, undefined)
  assert.equal(localDshHeaders(undefined, `${origin}/`, 'mainFrame', { 'Sec-Fetch-Site': 'none' }).Cookie, undefined)
})
