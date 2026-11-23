import assert from 'node:assert/strict'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin, phase, expected_context, output } = JSON.parse(input)
const browser = await puppeteer.launch({
  browser: process.env.AEGIS_BROWSER ?? 'firefox',
  executablePath: process.env.AEGIS_BROWSER_PATH ?? '/usr/bin/firefox',
  headless: true,
})
try {
  const page = await browser.newPage(),
    errors = []
  page.on('pageerror', (error) => errors.push(error.message))
  page.setDefaultTimeout(20000)
  await page.setViewport({ width: 1440, height: 1100 })
  async function button(label, selector = 'button') {
    await page.waitForFunction(
      (label, selector) =>
        [...document.querySelectorAll(selector)].some(
          (el) => el.textContent.trim().startsWith(label) && !el.disabled,
        ),
      {},
      label,
      selector,
    )
    for (const handle of await page.$$(selector)) {
      if (await handle.evaluate((el, text) => el.textContent.trim().startsWith(text), label)) {
        await handle.click()
        return
      }
    }
    throw new Error('Missing button: ' + label)
  }
  async function text(value) {
    await page.waitForFunction((value) => document.body.textContent.includes(value), {}, value)
  }
  async function openChild() {
    await page.waitForSelector('input[aria-label="Pesquisar técnica"]')
    await page.$eval('input[aria-label="Pesquisar técnica"]', (el) => {
      el.value = ''
    })
    await page.type('input[aria-label="Pesquisar técnica"]', 'T1059.001')
    await button('T1059.001', '.technique-cell')
    await text('Telemetria registrada nas execuções · Demo sintético')
  }
  async function api(path) {
    return page.evaluate(async (path) => {
      const response = await fetch('/api/v1' + path)
      if (!response.ok) throw new Error('API read failed: ' + response.status)
      return response.json()
    }, path)
  }
  await page.goto(origin, { waitUntil: 'networkidle0' })
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[type="password"]', password)
  await button('Entrar no workspace')
  await page.waitForSelector('main')
  await page.evaluate(() => {
    location.hash = 'attack'
  })
  await openChild()
  const child = await api('/techniques/T1059.001?mode=demo')
  const originalRelease = child.current_catalog.release_id
  assert.equal(child.observed_telemetry.length, 1)
  assert.equal(child.observed_telemetry[0].synthetic, true)
  assert.ok(child.observed_telemetry[0].sources.every((s) => s.synthetic && s.event_count > 0))
  if (phase === 'before') {
    assert.equal(child.catalog_context.status, 'legacy_unavailable')
    assert.equal(child.coverage, 'OBSERVED_NOT_ALERTED')
    await text('O snapshot legado não preserva referências de telemetria')
  } else {
    assert.equal(child.catalog_context.status, 'available')
    assert.equal(child.coverage, 'NOT_TESTED')
    assert.notEqual(child.observed_telemetry[0].catalog_release_id, originalRelease)
    assert.deepEqual(child.catalog_context.telemetry, expected_context.telemetry)
    await page.click('dialog .technique-context summary')
    const refs = expected_context.telemetry[0]
    for (const key of ['strategy', 'analytic', 'component']) {
      await page.waitForFunction(
        (id) =>
          [...document.querySelectorAll('dialog .telemetry-paths a')].some(
            (a) =>
              a.textContent.startsWith(id + ' ·') && a.href.startsWith('https://attack.mitre.org/'),
          ),
        {},
        refs[key].id,
      )
    }
    assert.equal(await page.$eval('dialog .telemetry-paths a', (el) => el.rel), 'noreferrer')
  }
  // Traverse exact parent/child IDs without changing matrix search, mode or release.
  await button('T1059 ·', 'dialog .technique-context button')
  await page.waitForFunction(() =>
    [...document.querySelectorAll('dialog h2')].some(
      (el) => el.textContent === 'Command and Scripting Interpreter',
    ),
  )
  const parent = await api('/techniques/T1059?mode=demo&catalog_release_id=' + originalRelease)
  assert.equal(parent.coverage, 'NOT_TESTED')
  assert.equal(parent.observed_telemetry.length, 0)
  await button('T1059.001 ·', 'dialog .technique-context button')
  await page.waitForFunction(() =>
    [...document.querySelectorAll('dialog h2')].some((el) => el.textContent === 'PowerShell'),
  )
  assert.equal(
    await page.$eval('input[aria-label="Pesquisar técnica"]', (el) => el.value),
    'T1059.001',
  )
  // Close using the real dialog action, then switch to real mode without any lab action.
  await page.click('dialog button[aria-label="Fechar"]')
  await page.select('select[aria-label="Modo da cobertura ATT&CK"]', 'linux')
  await button('T1059.001', '.technique-cell')
  await text('Telemetria registrada nas execuções · Linux real')
  await text('Nenhuma avaliação concluída neste modo.')
  const real = await api('/techniques/T1059.001?mode=linux&catalog_release_id=' + originalRelease)
  assert.deepEqual(real.observed_telemetry, [])
  assert.deepEqual(real.telemetry_sources, [])
  assert.equal(real.coverage, 'NOT_TESTED')
  await page.click('dialog button[aria-label="Fechar"]')
  await page.select('select[aria-label="Modo da cobertura ATT&CK"]', 'demo')
  await button('T1059.001', '.technique-cell')
  await text('Telemetria registrada nas execuções · Demo sintético')
  if (phase === 'after') await page.click('dialog .technique-context summary')
  for (const [name, width, height] of [
    ['desktop', 1440, 1100],
    ['mobile', 390, 844],
  ]) {
    await page.setViewport({ width, height })
    await page.$eval('dialog .technique-context', (el) => el.scrollIntoView())
    assert.equal(await page.$eval('dialog', (el) => el.scrollWidth <= el.clientWidth + 1), true)
    await page.screenshot({ path: `${output}/context-${phase}-${name}.png` })
  }
  assert.deepEqual(errors, [])
  console.log(
    JSON.stringify({
      phase,
      release_id: originalRelease,
      status: child.catalog_context.status,
      official_paths: child.catalog_context.telemetry.length,
      historical_release_id: child.observed_telemetry[0].catalog_release_id,
      parent_child_navigation: true,
      real_mode_has_no_demo_events: true,
      responsive_widths: [1440, 390],
      browser_errors: errors,
    }),
  )
} finally {
  await browser.close()
}
