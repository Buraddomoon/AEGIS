import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'
let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin, output, labs, assets } = JSON.parse(input)
const browser = await puppeteer.launch({
  browser: 'firefox',
  executablePath: '/usr/bin/firefox',
  headless: true,
})
const deadline = setTimeout(() => void browser.close(), 120000)
const errors = [],
  runs = []
try {
  const page = await browser.newPage()
  page.on('pageerror', (error) => errors.push(error.message))
  page.setDefaultTimeout(15000)
  await page.setViewport({ width: 1440, height: 1000 })
  async function button(text) {
    await page.waitForFunction(
      (t) =>
        [...document.querySelectorAll('button')].some(
          (b) => b.textContent.trim() === t && !b.disabled,
        ),
      {},
      text,
    )
    for (const node of await page.$$('button')) {
      if (await node.evaluate((el, text) => el.textContent.trim() === text, text)) {
        await node.click()
        return
      }
    }
    throw new Error('Missing button ' + text)
  }
  async function field(label, value) {
    const id = await page.evaluate((label) => {
      const element = [...document.querySelectorAll('label')]
        .find(
          (el) =>
            [...el.childNodes]
              .filter((n) => n.nodeType === Node.TEXT_NODE)
              .map((n) => n.textContent)
              .join('')
              .trim() === label,
        )
        ?.querySelector('input,select,textarea')
      assertElement(element)
      function assertElement(el) {
        if (!el) throw new Error('Missing field ' + label)
      }
      element.id ||= 'registry-field-' + Math.random().toString(16).slice(2)
      return element.id
    }, label)
    if ((await page.$eval('#' + id, (el) => el.tagName)) === 'SELECT')
      await page.select('#' + id, value)
    else {
      await page.locator('#' + id).fill(value)
    }
  }
  async function has(text) {
    await page.waitForFunction((t) => document.body.textContent.includes(t), {}, text)
  }
  async function api(path, body) {
    return page.evaluate(
      async (path, body) => {
        const csrf =
          document.cookie
            .split('; ')
            .find((x) => x.startsWith('aegis_csrf='))
            ?.split('=')[1] ?? ''
        const response = await fetch('/api/v1' + path, {
          method: body ? 'POST' : 'GET',
          headers: {
            'Content-Type': 'application/json',
            'X-Aegis-Request': 'browser',
            'X-CSRF-Token': csrf,
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        })
        if (!response.ok) throw new Error('API status ' + response.status + ' at ' + path)
        return response.json()
      },
      path,
      body,
    )
  }
  await page.goto(origin + '/#labs')
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[autocomplete="current-password"]', password)
  await button('Entrar no workspace')
  await has('Second Demo registry')
  await has('Windows no adapter')
  await button('Registrar Linux Lab')
  await page.waitForFunction(() =>
    [...document.querySelectorAll('option')].some((o) => o.value === 'offline-reviewed'),
  )
  await field('Conexão aprovada', 'offline-reviewed')
  await field('Nome', 'Offline registry fixture')
  await field(
    'Revisão do isolamento',
    'Offline browser review; no native transport, preflight or marker.',
  )
  await page.click('dialog input[type="checkbox"]')
  await button('Registrar binding')
  await has('Offline registry fixture')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  const registryLabs = await api('/labs')
  const registered = registryLabs.items.find((l) => l.name === 'Offline registry fixture')
  assert.equal(registered.authorized, false)
  assert.equal(registered.connection_status, 'disconnected')
  for (let i = 0; i < 2; i++) {
    await page.goto(origin + '/#campaigns')
    await button('Nova campanha')
    await page.waitForSelector('dialog[open]')
    await field('Nome da campanha', 'Registry Demo ' + i)
    await field('Objetivo', 'Synthetic isolation and exact asset selection.')
    await page.waitForFunction(
      (id) => [...document.querySelectorAll('option')].some((o) => o.value === id),
      {},
      labs[i],
    )
    await field('Laboratório', labs[i])
    await page.waitForFunction(
      (id) => [...document.querySelectorAll('option')].some((o) => o.value === id),
      {},
      assets[i],
    )
    await field('Ativo autorizado', assets[i])
    await page.waitForSelector('fieldset input[type="checkbox"]')
    await page.click('fieldset input[type="checkbox"]')
    await button('Criar campanha')
    await page.waitForFunction(() => !document.querySelector('dialog[open]'))
    const campaign = (await api('/campaigns?limit=1000')).items.find(
      (c) => c.name === 'Registry Demo ' + i,
    )
    assert.equal(campaign.asset_id, assets[i])
    const run = await api(`/campaigns/${campaign.id}/runs`, {
      idempotency_key: crypto.randomUUID().replaceAll('-', ''),
    })
    assert.equal(run.scope.asset_id, assets[i])
    assert.equal(run.scope.laboratory_id, labs[i])
    assert.equal(run.synthetic, true)
    await api(`/executions/${run.id}/approve`, { confirm_scope_hash: run.scope_hash })
    await api(`/executions/${run.id}/start`, { confirm: true })
    await page.waitForFunction(
      async (id) => (await (await fetch('/api/v1/executions/' + id)).json()).state === 'COMPLETED',
      {},
      run.id,
    )
    runs.push(run.id)
  }
  await page.goto(origin + '/#labs')
  await has('Second synthetic endpoint')
  await button('Histórico do ativo Second synthetic endpoint')
  await has('COMPLETED')
  const history = await api('/assets/' + assets[1] + '/history')
  assert.equal(history.total, 1)
  assert.equal(history.items[0].run_id, runs[1])
  assert.equal(history.items[0].synthetic, true)
  await page.click('dialog button[aria-label="Fechar"]')
  const notification = await page.$('button[aria-label="Dispensar mensagem"]')
  if (notification) await notification.click()
  for (const width of [1440, 390]) {
    await page.setViewport({ width, height: 1000 })
    await page.waitForFunction(
      (w) =>
        innerWidth === w &&
        (w > 850 || document.querySelector('.sidebar').getBoundingClientRect().right <= 0),
      {},
      width,
    )
    assert(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
      'Page overflow',
    )
    assert(
      await page.$$eval(
        '.lab-asset .mono',
        (nodes) =>
          nodes.length === 4 && nodes.every((node) => node.getBoundingClientRect().height < 200),
      ),
      'Asset identity text is compressed or unreadable',
    )
    await page.screenshot({ path: `${output}/labs-${width}.png`, fullPage: true })
  }
  assert.deepEqual(errors, [])
  await writeFile(
    output + '/browser-summary.json',
    JSON.stringify(
      {
        completed_synthetic_runs: runs,
        screenshots: 2,
        js_errors: errors,
        offline_registration_revoked: true,
        exact_asset_history_verified: true,
      },
      null,
      2,
    ),
  )
} finally {
  clearTimeout(deadline)
  await browser.close()
}
