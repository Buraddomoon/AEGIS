// UI-only acceptance against an explicitly supplied disposable Demo instance.
// Credentials arrive on stdin; screenshots stay in the ignored local directory.
import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin } = JSON.parse(input)
assert(['localhost', '127.0.0.1'].includes(new URL(origin).hostname))
const output = process.env.AEGIS_UI_SCREENSHOTS ?? '../../.local/frontend-preview/workspace'
await mkdir(output, { recursive: true })
const browser = await puppeteer.launch({
  browser: 'firefox',
  executablePath: '/usr/bin/firefox',
  headless: true,
})
const errors = [],
  checks = []
try {
  const page = await browser.newPage()
  page.on('pageerror', (error) => errors.push(error.message))
  page.setDefaultTimeout(15000)
  await page.setViewport({ width: 1440, height: 1000, deviceScaleFactor: 1 })
  await page.goto(origin, { waitUntil: 'networkidle0' })
  await page.waitForSelector('input[autocomplete="username"]')
  assert.equal(
    await page.$('.login-card [role="status"]'),
    null,
    'Fresh visit must not claim an expired session',
  )
  await page.screenshot({ path: `${output}/login-desktop.png`, fullPage: true })
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 })
  assert(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    'Mobile login overflow',
  )
  await page.screenshot({ path: `${output}/login-mobile.png`, fullPage: true })
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[autocomplete="current-password"]', password)
  await page.click('button[aria-label="Mostrar senha"]')
  assert.equal(await page.$eval('#login-password', (element) => element.type), 'text')
  await page.click('button[aria-label="Ocultar senha"]')
  // A periodic anonymous check used to detach the identity query from the UI.
  // Reproduce that transition before submitting valid credentials.
  await page.evaluate(() =>
    window.dispatchEvent(
      new CustomEvent('aegis-session-ended', {
        detail: 'Sessão expirada ou revogada. Entre novamente.',
      }),
    ),
  )
  await page.click('button[type="submit"]')
  await page.waitForSelector('.stats-grid')
  const identity = await page.evaluate(async () => {
    const response = await fetch('/api/v1/auth/me')
    if (!response.ok) throw new Error(`Session not established: ${response.status}`)
    const user = await response.json()
    return { username: user.username, role: user.role }
  })
  assert.equal(identity.username, username)
  assert.equal(identity.role, 'administrator')
  checks.push('login, password visibility, fresh-session message and mobile layout')

  await page.click('button[aria-label="Abrir menu"]')
  await page.waitForSelector('.sidebar[aria-modal="true"]')
  assert(await page.$eval('.main-shell', (element) => element.inert))
  const bounds = await page.$eval('.sidebar', (element) => {
    const items = [...element.querySelectorAll('a[href], button:not([disabled])')]
    items[0].focus()
    return {
      first: items[0].getAttribute('aria-label'),
      last: items.at(-1).getAttribute('aria-label'),
    }
  })
  await page.keyboard.down('Shift')
  await page.keyboard.press('Tab')
  await page.keyboard.up('Shift')
  assert.equal(
    await page.evaluate(() => document.activeElement.getAttribute('aria-label')),
    bounds.last,
  )
  await page.keyboard.press('Tab')
  assert.equal(
    await page.evaluate(() => document.activeElement.getAttribute('aria-label')),
    bounds.first,
  )
  await page.screenshot({ path: `${output}/navigation-mobile.png`, fullPage: false })
  await page.keyboard.press('Escape')
  assert.equal(await page.$eval('.main-shell', (element) => element.inert), false)
  assert.equal(
    await page.evaluate(() => document.activeElement.getAttribute('aria-label')),
    'Abrir menu',
  )
  await page.click('button[aria-label="Abrir menu"]')
  await page.click('.sidebar a[href="#overview"]')
  await page.waitForFunction(
    () => !document.querySelector('.sidebar').classList.contains('mobile-open'),
  )
  checks.push('mobile focus trap, Escape, focus return and closing the current route')

  await page.setViewport({ width: 1440, height: 1000, deviceScaleFactor: 1 })
  await page.click('button[aria-label="Buscar página"]')
  await page.waitForSelector('dialog[open] input[type="search"]')
  assert.equal(
    await page.evaluate(() => document.activeElement.getAttribute('aria-label')),
    'Pesquisar páginas',
  )
  await page.type('input[aria-label="Pesquisar páginas"]', 'relatorios')
  await page.screenshot({ path: `${output}/quick-navigation.png`, fullPage: false })
  await page.keyboard.press('Enter')
  await page.waitForFunction(
    () => location.hash === '#reports' && document.activeElement.id === 'main',
  )
  await page.keyboard.down('Control')
  await page.keyboard.press('k')
  await page.keyboard.up('Control')
  await page.waitForSelector('dialog[open]')
  await page.keyboard.press('Escape')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  checks.push('accent-insensitive page search, Enter, Ctrl K and route focus')

  const routes = [
    'overview',
    'attack',
    'tests',
    'campaigns',
    'executions',
    'schedules',
    'coverage',
    'rules',
    'reports',
    'labs',
    'settings',
  ]
  for (const width of [1440, 768, 390]) {
    await page.setViewport({ width, height: width === 1440 ? 1000 : 844, deviceScaleFactor: 1 })
    for (const route of routes) {
      await page.evaluate((route) => {
        location.hash = route
      }, route)
      await page.waitForFunction(
        (route) =>
          document.querySelector('.nav-item[aria-current="page"]')?.getAttribute('href') ===
          `#${route}`,
        {},
        route,
      )
      await page.waitForFunction(() => !document.querySelector('main .loading'))
      const dimensions = await page.evaluate(() => ({
        viewport: innerWidth,
        document: document.documentElement.scrollWidth,
      }))
      assert(
        dimensions.document <= dimensions.viewport,
        `${route} overflows at ${width}px: ${JSON.stringify(dimensions)}`,
      )
      if ([1440, 390].includes(width))
        await page.screenshot({ path: `${output}/${route}-${width}.png`, fullPage: true })
    }
  }
  checks.push('all 11 primary pages without document overflow at 1440, 768 and 390 pixels')
  assert.deepEqual(errors, [])
  const result = {
    checks,
    browserErrors: errors,
    routes: routes.length,
    widths: [1440, 768, 390],
    mode: 'synthetic Demo; UI-only; no native labs',
  }
  await writeFile(`${output}/result.json`, JSON.stringify(result, null, 2))
  console.log(JSON.stringify(result))
} finally {
  await browser.close()
}
