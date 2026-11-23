import assert from 'node:assert/strict'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin, phase, plan_id, stale_id, output } = JSON.parse(input)
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
  async function button(label) {
    await page.waitForFunction(
      (text) =>
        [...document.querySelectorAll('button')].some(
          (el) => el.textContent.trim() === text && !el.disabled,
        ),
      {},
      label,
    )
    for (const handle of await page.$$('button')) {
      if (await handle.evaluate((el, text) => el.textContent.trim() === text, label)) {
        await handle.click()
        return
      }
    }
    throw new Error('Missing button: ' + label)
  }
  async function text(value) {
    await page.waitForFunction((value) => document.body.textContent.includes(value), {}, value)
  }
  async function inspect(id) {
    await page.waitForFunction(
      (id) =>
        [...document.querySelectorAll('dialog .panel')].some((el) => el.textContent.includes(id)),
      {},
      id,
    )
    for (const panel of await page.$$('dialog .panel')) {
      if (await panel.evaluate((el, id) => el.textContent.includes(id), id)) {
        await panel.$eval('button', (el) => el.click())
        return
      }
    }
    throw new Error('Plan not found')
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
  await button('Revisar atualização ATT&CK')
  await inspect(phase === 'before' ? plan_id : stale_id)
  if (phase === 'after') {
    await text('Plano/candidato mudou ou está indisponível')
    assert.equal(await page.$('dialog input[type="checkbox"]'), null)
    await button('Voltar aos planos')
    await inspect(plan_id)
    await text('Já aplicado')
    assert.equal(await page.$eval('dialog input[type="checkbox"]', (el) => el.disabled), true)
  } else {
    await text('Ainda não aplicado')
    await text(plan_id)
    assert.equal(await page.$eval('dialog input[type="checkbox"]', (el) => el.checked), false)
    // Exercise a real diff page before the exact-hash acknowledgement.
    await button('Próxima · mudanças')
    await text('Página 2')
    await page.waitForSelector('dialog input[type="checkbox"]')
    assert.equal(await page.$eval('dialog input[type="checkbox"]', (el) => el.checked), false)
    await page.click('dialog input[type="checkbox"]')
    await button('Validar instrução local')
    await text('Instrução validada')
    const command = await page.$eval('dialog [role="status"] pre', (el) => el.textContent)
    assert.ok(command.includes('--confirm-plan ' + plan_id))
    assert.ok(command.includes('scripts/update_attack.py apply'))
  }
  await page.$eval('dialog', (el) => {
    el.scrollTop = 0
  })
  await page.screenshot({ path: `${output}/${phase}-desktop.png` })
  await page.setViewport({ width: 390, height: 844 })
  await page.$eval('dialog', (el) => {
    el.scrollTop = 0
  })
  await page.screenshot({ path: `${output}/${phase}-mobile.png` })
  if (phase === 'before') {
    await page.$eval('dialog', (el) => {
      el.scrollTop = el.scrollHeight
    })
    await page.screenshot({ path: `${output}/instruction-mobile.png` })
  }
  const layout = await page.$eval('dialog', (el) => ({
    width: el.getBoundingClientRect().width,
    client: el.clientWidth,
    scroll: el.scrollWidth,
  }))
  assert.ok(layout.width <= 390 && layout.scroll <= layout.client + 1, JSON.stringify(layout))
  const buttonsInside = await page.$eval('dialog', (dialog) => {
    const bounds = dialog.getBoundingClientRect()
    return [...dialog.querySelectorAll('.pagination button')].every((button) => {
      const rect = button.getBoundingClientRect()
      return rect.left >= bounds.left && rect.right <= bounds.right
    })
  })
  assert.ok(buttonsInside, 'Mobile pagination controls must remain inside the dialog')
  assert.deepEqual(errors, [])
  console.log(
    JSON.stringify({
      phase,
      plan_sha256: plan_id,
      browser: 'Firefox',
      javascript_errors: errors.length,
      mobile: layout,
      status: 'VERIFIED',
    }),
  )
} finally {
  await browser.close()
}
