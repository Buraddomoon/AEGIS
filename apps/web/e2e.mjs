import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin } = JSON.parse(input)
const browser = await puppeteer.launch({
  browser: process.env.AEGIS_BROWSER ?? 'firefox',
  executablePath: process.env.AEGIS_BROWSER_PATH ?? '/usr/bin/firefox',
  headless: true,
})
const page = await browser.newPage(),
  errors = []
page.on('pageerror', (e) => errors.push(e.message))
page.setDefaultTimeout(20000)
await page.setViewport({ width: 1440, height: 1100, deviceScaleFactor: 1 })
await mkdir('../../docs/images', { recursive: true })
async function button(text, selector = 'button') {
  await page.waitForFunction(
    (text, selector) =>
      [...document.querySelectorAll(selector)].some(
        (b) => b.textContent.trim() === text && !b.disabled,
      ),
    {},
    text,
    selector,
  )
  const handles = await page.$$(selector)
  for (const handle of handles)
    if (await handle.evaluate((el, text) => el.textContent.trim() === text, text)) {
      await handle.click()
      return
    }
  throw new Error('Button missing: ' + text)
}
async function text(value) {
  await page.waitForFunction(
    (t) => document.querySelector('main')?.textContent.includes(t),
    {},
    value,
  )
}
async function navigate(hash) {
  await page.evaluate((hash) => {
    location.hash = hash
  }, hash)
}
async function screenshot(name) {
  const dismiss = await page.$('button[aria-label="Dispensar mensagem"]')
  if (dismiss) await dismiss.click()
  await page.screenshot({ path: `../../docs/images/${name}.png`, fullPage: true })
}
async function approveAndRun() {
  await button('Revisar e aprovar')
  await page.click('dialog input[type="checkbox"]')
  await button('Aprovar escopo', 'dialog button')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  await button('Confirmar e iniciar')
  await text('Execução e cleanup demonstrativos concluídos.')
  await text('Detectado')
  await text('Observado sem alerta')
  await text('Sem telemetria')
  await text('Inconclusivo')
}
try {
  await page.goto(origin, { waitUntil: 'networkidle0' })
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[autocomplete="current-password"]', password)
  await button('Entrar no workspace')
  await text('Visão geral')
  await navigate('attack')
  await text('706 técnicas')
  await page.locator('input[aria-label="Pesquisar técnica"]').fill('T1059.004')
  await text('1 técnicas no filtro atual')
  await page.click('button[aria-label="Visualização em tabela"]')
  await button('T1059.004')
  await page.waitForSelector('dialog[open]')
  await page.click('dialog button[aria-label="Fechar"]')
  await navigate('campaigns')
  await button('Nova campanha')
  await page.locator('dialog input[minlength="3"]').fill('Endpoint Detection Validation')
  await page.type(
    'dialog textarea',
    'Validar a correlação de processos e marcadores no Demo Lab, com evidências sintéticas e limitações explícitas.',
  )
  const labValue = await page.$eval('dialog select', (el) => el.options[1].value)
  await page.select('dialog select', labValue)
  const checks = await page.$$('dialog input[type="checkbox"]')
  for (const check of checks) await check.click()
  await button('Criar campanha', 'dialog button')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  await button('Solicitar execução')
  await page.waitForFunction(() => location.hash.includes('executions/'))
  const firstId = await page.evaluate(() => location.hash.split('/')[1])
  await approveAndRun()
  await screenshot('execution')
  const evidence = await page.$('.evidence-button')
  await evidence.click()
  await page.waitForSelector('dialog[open] pre')
  assert.match(await page.$eval('dialog pre', (el) => el.textContent), /"synthetic": true/)
  await page.click('dialog button[aria-label="Fechar"]')
  const response = page.waitForResponse((r) => r.url().includes(`/reports/${firstId}?format=json`))
  await button('JSON')
  assert.equal((await response).status(), 200)
  const report = await page.evaluate(
    async (id) => (await fetch('/api/v1/reports/' + id)).json(),
    firstId,
  )
  assert.equal(report.synthetic, true)
  assert.equal(report.run.executions.length, 4)
  await button('Repetir campanha')
  await page.waitForFunction((id) => location.hash !== `#executions/${id}`, {}, firstId)
  const secondId = await page.evaluate(() => location.hash.split('/')[1])
  await approveAndRun()
  await navigate('coverage')
  await text('Comparação entre execuções')
  await page.select('.comparison-form select', firstId)
  const selects = await page.$$('.comparison-form select')
  await selects[1].select(secondId)
  await button('Comparar execuções')
  await text('Configurações equivalentes')
  assert.equal(await page.$eval('tbody', (el) => el.querySelectorAll('tr').length), 4)
  await navigate('overview')
  await text('8 testes concluídos')
  const coverage = await page.evaluate(async () => (await fetch('/api/v1/coverage')).json())
  assert.equal(coverage.valid_tests, 6)
  assert.equal(coverage.detected_percentage, 33.3)
  await screenshot('overview')
  await navigate('attack')
  await text('706 técnicas')
  await screenshot('attack')
  await navigate('schedules')
  await text('Agendamentos')
  await button('Novo agendamento')
  const campaignValue = await page.$eval('dialog select', (el) => el.options[1].value)
  await page.select('dialog select', campaignValue)
  await page.evaluate(() => {
    const format = (ms) => {
      const d = new Date(ms)
      return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19)
    }
    const fields = [...document.querySelectorAll('dialog input')]
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
    for (const [el, value] of [[fields[0], format(Date.now() + 15000)], [fields[1], format(Date.now() + 300000)], [fields[3], '1']]) {
      set.call(el, value)
      el.dispatchEvent(new Event('input', { bubbles: true }))
      el.dispatchEvent(new Event('change', { bubbles: true }))
    }
  })
  await button('Criar plano', 'dialog button')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  await button('Revisar autorização recorrente')
  await page.click('dialog input[type="checkbox"]')
  await button('Autorizar plano Demo', 'dialog button')
  await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  await text('Limite encerrado')
  await text('Ver execução')
  await screenshot('schedules')
  await button('Ver execução', 'main a')
  await text('Execução e cleanup demonstrativos concluídos.')
  await text('Execução automática autorizada.')
  const scheduledId = await page.evaluate(() => location.hash.split('/')[1])
  const scheduledReport = await page.evaluate(async id => (await fetch('/api/v1/reports/' + id)).json(), scheduledId)
  assert.equal(scheduledReport.synthetic, true)
  assert.equal(scheduledReport.run.state, 'COMPLETED')
  assert.equal(scheduledReport.run.approval.schedule_authorization_id, scheduledReport.run.schedule_occurrence.authorization_id)
  assert.ok(scheduledReport.run.schedule_id)
  assert.equal(scheduledReport.run.schedule_plan.plan_hash, scheduledReport.run.schedule_authorization.plan_hash)
  const sigma = `title: AEGIS demo planning review
id: 8b065c14-928c-4f6c-898c-aef9e9729028
status: experimental
description: Synthetic demonstration of planning metadata; not deployed
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: aegis-marker
  condition: selection
tags:
  - attack.t1059.004
level: informational
`
  async function importSigma(content) {
    await button('Importar regra Sigma')
    await page.type('dialog textarea', content)
    const saved = page.waitForResponse(r => r.url().endsWith('/api/v1/rules') && r.request().method() === 'POST')
    await button('Validar e salvar', 'dialog button')
    assert.equal((await saved).status(), 201, 'Sigma import must succeed')
    await page.waitForFunction(() => !document.querySelector('dialog[open]'))
  }
  async function reviewLink() {
    await page.select('dialog form select', 'demo-shell')
    await page.type('dialog form textarea', 'Planejamento Demo: avaliar a fonte de criação de processos e o comportamento benigno de shell. Não comprova implantação nem detecção.')
    await page.waitForFunction(() => {
      const checkbox = document.querySelector('dialog form input[type="checkbox"]')
      return checkbox && !checkbox.disabled
    })
    await page.$eval('dialog form input[type="checkbox"]', el => el.scrollIntoView({block: 'center'}))
    await page.locator('dialog form input[type="checkbox"]').click()
    await page.waitForFunction(() => document.querySelector('dialog form input[type="checkbox"]')?.checked)
    await button('Registrar revisão', 'dialog button')
    await page.waitForFunction(() => document.querySelector('dialog form textarea')?.value === '')
  }
  await navigate('rules')
  await importSigma(sigma)
  await button('Testes e revisões')
  await reviewLink()
  await text('Revisado para planejamento')
  await screenshot('rule-test-links')
  await page.click('dialog button[aria-label="Fechar"]')
  await navigate('campaigns')
  await button('Solicitar execução')
  await page.waitForFunction(() => location.hash.includes('executions/'))
  const reviewedId = await page.evaluate(() => location.hash.split('/')[1])
  await approveAndRun()
  const reviewedReport = await page.evaluate(async id => (await fetch('/api/v1/reports/' + id)).json(), reviewedId)
  assert.equal(reviewedReport.run.scope.rule_test_links.length, 1)
  assert.equal(reviewedReport.run.scope.rule_test_links[0].rule_version, 1)
  await navigate('rules')
  await importSigma(sigma.replace('level: informational', 'level: low'))
  await button('Testes e revisões')
  await text('Revisão necessária')
  await reviewLink()
  await button('Retirar vínculo', 'dialog button')
  await button('Confirmar retirada', 'dialog button')
  await text('Nenhum vínculo registrado')
  await page.click('dialog .toolbar input[type="checkbox"]')
  await text('Retirado')
  await page.click('dialog button[aria-label="Fechar"]')
  const historicalReport = await page.evaluate(async id => (await fetch('/api/v1/reports/' + id)).json(), reviewedId)
  assert.deepEqual(historicalReport, reviewedReport, 'Rule reviews must not rewrite historical reports')
  await navigate('coverage')
  await page.select('.comparison-form select', firstId)
  const diffSelects = await page.$$('.comparison-form select')
  await diffSelects[1].select(reviewedId)
  await button('Comparar execuções')
  await text('Configurações diferentes')
  await text('Versões do inventário Sigma · 1 alteração(ões)')
  await text('Associações entre regras e testes · 1 alteração(ões)')
  await screenshot('scope-comparison')
  for (const [route, heading] of [
    ['tests', 'Biblioteca de testes'],
    ['reports', 'Relatórios'],
    ['labs', 'Laboratórios'],
    ['rules', 'Regras de detecção'],
    ['settings', 'Configurações'],
  ]) {
    await navigate(route)
    await text(heading)
  }
  await text('Desconectado')
  await screenshot('wazuh-preparation')
  await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 })
  await navigate('overview')
  await text('16 testes concluídos')
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    true,
    'Mobile layout overflow',
  )
  await screenshot('mobile')
  assert.deepEqual(errors, [], 'Browser errors')
  console.log(
    JSON.stringify({
      result: 'PASS',
      flow: 'login → catalog → campaign → approval → worker → evidence → metrics → export → repeat → compare → approved schedule → automatic run → originating grant report → Sigma review → version change → retirement → historical scope comparison',
      runs: 4,
      tests: 16,
      browser: process.env.AEGIS_BROWSER ?? 'firefox',
      screenshots: 8,
      browserErrors: errors.length,
    }),
  )
} catch (error) {
  await page.screenshot({ path: '../../.local/e2e/failure.png', fullPage: true })
  throw error
} finally {
  await browser.close()
}
