import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, replacement, origin, output } = JSON.parse(input)
const browser = await puppeteer.launch({
  browser: 'firefox',
  executablePath: '/usr/bin/firefox',
  headless: true,
})
const watchdog = setTimeout(() => {
  console.error('Account browser deadline exceeded')
  void browser.close()
}, 120000)
const errors = [],
  summary = { accounts: 3, screenshots: 0, checks: [] }
const page = await browser.newPage()
page.on('pageerror', (e) => errors.push(e.message))
page.setDefaultTimeout(15000)
await page.setViewport({ width: 1440, height: 1000 })
async function button(page, text) {
  console.log('button', text)
  await page.bringToFront()
  await page.waitForFunction(
    (text) =>
      [...document.querySelectorAll('button')].some(
        (b) => b.textContent.trim() === text && !b.disabled,
      ),
    {},
    text,
  )
  for (const b of await page.$$('button')) {
    if (await b.evaluate((el, text) => el.textContent.trim() === text, text)) {
      await b.evaluate((el) => el.scrollIntoView({ block: 'center', inline: 'center' }))
      await page.waitForFunction(
        (el) => {
          const r = el.getBoundingClientRect()
          const hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)
          return hit === el || el.contains(hit)
        },
        {},
        b,
      )
      await b.click()
      return
    }
  }
  throw new Error('Missing button: ' + text)
}
async function label(page, text, value) {
  await page.bringToFront()
  await page.waitForFunction(
    (text) =>
      [...document.querySelectorAll('label')].some(
        (l) =>
          [...l.childNodes]
            .filter((n) => n.nodeType === Node.TEXT_NODE)
            .map((n) => n.textContent)
            .join('')
            .trim() === text && l.querySelector('input,select'),
      ),
    {},
    text,
  )
  const selector = await page.evaluate((text) => {
    const label = [...document.querySelectorAll('label')].find(
      (l) =>
        [...l.childNodes]
          .filter((n) => n.nodeType === Node.TEXT_NODE)
          .map((n) => n.textContent)
          .join('')
          .trim() === text,
    )
    const input = label?.querySelector('input,select')
    if (!input) throw new Error('Missing field: ' + text)
    input.id ||= 'e2e-field-' + Math.random().toString(16).slice(2)
    return '#' + input.id
  }, text)
  if ((await page.$eval(selector, (el) => el.tagName)) === 'SELECT')
    await page.select(selector, value)
  else {
    await page.$eval(selector, (el) => {
      el.value = ''
    })
    await page.type(selector, value)
  }
}
async function has(page, text) {
  await page.bringToFront()
  await page.waitForFunction((t) => document.body.textContent.includes(t), {}, text)
}
async function login(page, name, secret) {
  await page.bringToFront()
  await page.goto(origin + '/#settings')
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', name)
  await page.type('input[autocomplete="current-password"]', secret)
  await button(page, 'Entrar no workspace')
  await has(page, 'Minha conta')
}
async function shot(name, width = 1440) {
  await page.setViewport({ width, height: 1000 })
  await page.waitForFunction(
    (width) =>
      innerWidth === width &&
      (width > 850 || document.querySelector('.sidebar').getBoundingClientRect().right <= 0),
    {},
    width,
  )
  assert(
    await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    'viewport overflow',
  )
  await page.evaluate(() => scrollTo(0, 0))
  await page.screenshot({ path: output + '/' + name + '.png', fullPage: false })
  summary.screenshots++
}
async function save(page) {
  const response = page.waitForResponse(
    (r) => r.request().method() === 'PATCH' && r.url().includes('/api/v1/users/'),
  )
  await button(page, 'Salvar conta')
  assert.equal((await response).status(), 200)
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
}
async function closeDialog(page) {
  await page.bringToFront()
  const buttons = await page.$$('dialog[open] button[aria-label="Fechar"]')
  const count = buttons.length
  await buttons.at(-1).click()
  await page.waitForFunction(
    (count) => document.querySelectorAll('dialog[open] button[aria-label="Fechar"]').length < count,
    {},
    count,
  )
}
try {
  await login(page, username, password)
  await button(page, 'Administrar ' + username)
  await label(page, 'Papel da conta', 'viewer')
  await page.click('dialog input[type="checkbox"]:not(:checked)')
  await button(page, 'Salvar conta')
  await has(page, 'O último administrador ativo deve ser preservado.')
  await shot('last-admin')
  await closeDialog(page)
  summary.checks.push('last active administrator preserved')
  const target = username + '-target',
    operator = username + '-operator'
  for (const [name, role] of [
    [target, 'viewer'],
    [operator, 'operator'],
  ]) {
    await button(page, 'Adicionar usuário')
    await label(page, 'Usuário', name)
    await label(page, 'Senha inicial', password)
    await label(page, 'Papel', role)
    await button(page, 'Criar usuário')
    await has(page, 'Administrar ' + name)
  }
  const context = await browser.createBrowserContext(),
    other = await context.newPage()
  other.on('pageerror', (e) => errors.push(e.message))
  await login(other, target, password)
  assert(!(await other.evaluate(() => document.body.textContent.includes('Adicionar usuário'))))
  const denied = await other.evaluate(async () => (await fetch('/api/v1/users')).status)
  assert.equal(denied, 403)
  summary.checks.push('viewer administration denied by UI and API')
  await button(page, 'Administrar ' + target)
  await label(page, 'Papel da conta', 'operator')
  await page.click('dialog input[type="checkbox"]:not(:checked)')
  await save(page)
  await has(page, 'Conta atualizada; sessões afetadas encerradas.')
  assert.equal(await other.evaluate(async () => (await fetch('/api/v1/auth/me')).status), 401)
  // The app must clear cached privileges when its own request receives 401.
  await button(other, 'Encerrar todas as sessões')
  await button(other, 'Confirmar encerramento')
  await other.waitForSelector('input[autocomplete="username"]')
  await login(other, target, password)
  await has(other, 'Administração restrita')
  summary.checks.push(
    'old viewer session revoked after role change; operator has no administration',
  )
  await button(page, 'Administrar ' + target)
  await button(page, 'Redefinir senha desta conta')
  await label(page, 'Nova senha', replacement)
  await label(page, 'Confirmar nova senha', replacement)
  await button(page, 'Confirmar troca de senha')
  await has(page, 'Senha redefinida; as sessões da conta foram encerradas.')
  assert.equal(await other.evaluate(async () => (await fetch('/api/v1/auth/me')).status), 401)
  await closeDialog(page)
  await other.reload()
  await login(other, target, replacement)
  await button(page, 'Administrar ' + target)
  await page.click('dialog input[type="checkbox"]:checked')
  // The first checkbox is account active, the second explicitly confirms the edit.
  await page.evaluate(() => {
    const checks = document.querySelectorAll('dialog[open] form input[type="checkbox"]')
    if (!checks[1].checked) checks[1].click()
  })
  await save(page)
  assert.equal(await other.evaluate(async () => (await fetch('/api/v1/auth/me')).status), 401)
  await other.reload()
  await other.waitForSelector('input[autocomplete="username"]')
  await other.type('input[autocomplete="username"]', target)
  await other.type('input[autocomplete="current-password"]', replacement)
  await button(other, 'Entrar no workspace')
  await has(other, 'Credenciais inválidas.')
  summary.checks.push('password reset revokes session; inactive account cannot login')
  await button(page, 'Administrar ' + target)
  await page.evaluate(() =>
    document.querySelector('dialog[open] form input[type="checkbox"]').click(),
  )
  await page.evaluate(() =>
    document.querySelectorAll('dialog[open] form input[type="checkbox"]')[1].click(),
  )
  await save(page)
  await context.close()
  const opContext = await browser.createBrowserContext(),
    op = await opContext.newPage()
  await login(op, operator, password)
  assert(!(await op.evaluate(() => document.body.textContent.includes('Adicionar usuário'))))
  await button(op, 'Trocar minha senha')
  await label(op, 'Senha atual', password)
  await label(op, 'Nova senha', replacement)
  await label(op, 'Confirmar nova senha', replacement)
  await button(op, 'Confirmar troca de senha')
  await op.waitForSelector('input[autocomplete="username"]')
  await login(op, operator, replacement)
  await button(op, 'Encerrar todas as sessões')
  await button(op, 'Confirmar encerramento')
  await op.waitForSelector('input[autocomplete="username"]')
  await opContext.close()
  summary.checks.push('own password change and self session revocation require login again')
  await shot('accounts-desktop')
  await shot('accounts-mobile', 390)
  assert.equal(errors.length, 0)
  summary.javascript_errors = errors.length
  await writeFile(output + '/browser-summary.json', JSON.stringify(summary, null, 2) + '\n')
} catch (error) {
  await page.screenshot({ path: output + '/failure.png' }).catch(() => {})
  throw error
} finally {
  clearTimeout(watchdog)
  await browser.close()
}
