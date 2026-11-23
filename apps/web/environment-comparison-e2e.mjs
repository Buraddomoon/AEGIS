import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'

let raw = ''
for await (const chunk of process.stdin) raw += chunk
const { username, password, origin, output, before, after, campaign } = JSON.parse(raw)
const browser = await puppeteer.launch({
  browser: process.env.AEGIS_BROWSER ?? 'firefox',
  executablePath: process.env.AEGIS_BROWSER_PATH ?? '/usr/bin/firefox',
  headless: true,
})
try {
  let lastRaw, pdfSourceHash
  const page = await browser.newPage(),
    errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  page.setDefaultTimeout(20000)
  await page.setViewport({ width: 1440, height: 1100 })
  async function button(label) {
    await page.waitForFunction(
      (text) =>
        [...document.querySelectorAll('button')].some(
          (b) => b.textContent.trim() === text && !b.disabled,
        ),
      {},
      label,
    )
    for (const b of await page.$$('button')) {
      if (await b.evaluate((el, text) => el.textContent.trim() === text, label)) {
        await b.click()
        return
      }
    }
    throw new Error('Missing button: ' + label)
  }
  async function text(value) {
    await page.waitForFunction((v) => document.body.textContent.includes(v), {}, value)
  }
  async function query() {
    const response = page.waitForResponse((r) => r.url().includes('/coverage/environments?'))
    await button('Consultar laboratórios')
    const loaded = await response
    assert.equal(loaded.status(), 200)
    lastRaw = await loaded.text()
    return JSON.parse(lastRaw)
  }
  await page.goto(origin, { waitUntil: 'networkidle0' })
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[type="password"]', password)
  await button('Entrar no workspace')
  await page.waitForSelector('main')
  await page.evaluate(() => {
    location.hash = 'coverage'
  })
  await button('Escolher dois laboratórios')
  await page.waitForFunction(
    (id) => document.querySelector(`[aria-label="Laboratório B"] option[value="${id}"]`),
    {},
    after,
  )
  await page.select('[aria-label="Laboratório A"]', before)
  await page.select('[aria-label="Laboratório B"]', after)
  const preview = await query()
  assert.equal(preview.comparison.classification, 'equivalent')
  await text('Equivalência limitada aos registros')
  await writeFile(output + '/preview.json', lastRaw)
  for (const format of ['pdf', 'html', 'json']) {
    const response = page.waitForResponse(
      (r) =>
        r.url().includes('/coverage/environments/report?') && r.url().includes('format=' + format),
    )
    await button('Exportar laboratórios ' + format.toUpperCase())
    const download = await response
    assert.equal(download.status(), 200)
    // AEGIS Python encoding preserves floats (0.0); JS JSON.stringify changes
    // their representation. Verify against original JSON bytes in the Python harness.
    if (format === 'pdf') pdfSourceHash = download.headers()['x-aegis-report-sha256']
    await writeFile(output + '/comparison.' + format, Buffer.from(await download.buffer()))
  }
  await page.screenshot({ path: output + '/desktop.png', fullPage: true })
  await page.select('[aria-label="Release B"]', 'legacy')
  assert.equal(
    await page.evaluate(() =>
      [...document.querySelectorAll('button')].some((b) =>
        b.textContent.includes('Exportar laboratórios'),
      ),
    ),
    false,
  )
  assert.equal((await query()).comparison.classification, 'incomparable')
  await text('Recortes incomparáveis · sem delta')
  await page.select('[aria-label="Release B"]', 'all')
  await query()
  // New synthetic request via the normal API changes membership; no historical rewrite.
  const created = await page.evaluate(async (campaign) => {
    const csrf = document.cookie
      .split('; ')
      .find((s) => s.startsWith('aegis_csrf='))
      ?.split('=')[1]
    const response = await fetch(`/api/v1/campaigns/${campaign}/runs`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-csrf-token': csrf,
        'x-aegis-request': 'browser',
      },
      body: JSON.stringify({ idempotency_key: crypto.randomUUID() }),
    })
    return { status: response.status, run: await response.json() }
  }, campaign)
  assert.equal(created.status, 201)
  assert.equal(created.run.state, 'PENDING_APPROVAL')
  const conflict = page.waitForResponse((r) => r.url().includes('/coverage/environments/report?'))
  await button('Exportar laboratórios JSON')
  assert.equal((await conflict).status(), 409)
  await text('Snapshot mudou; consulte novamente')
  const descriptive = await query()
  assert.equal(descriptive.comparison.classification, 'descriptive')
  assert.equal(descriptive.comparison.detected_rate_delta_percentage_points, null)
  await text('Comparação descritiva · sem delta')
  await page.setViewport({ width: 390, height: 844 })
  await page.screenshot({ path: output + '/mobile.png', fullPage: true })
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)
  assert.equal(overflow, false, 'Mobile document overflow')
  assert.deepEqual(errors, [])
  console.log(
    JSON.stringify({
      status: 'VERIFIED',
      pdf_source_sha256: pdfSourceHash,
      errors,
      export_formats: ['pdf', 'html', 'json'],
      states: ['equivalent', 'incomparable', 'descriptive'],
      export_drift_status: 409,
      pending_synthetic_run: created.run.id,
      mobile_overflow: overflow,
    }),
  )
} finally {
  await browser.close()
}
