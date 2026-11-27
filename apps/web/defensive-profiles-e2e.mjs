import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'
let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, origin, output, lab_id } = JSON.parse(input)
const browser = await puppeteer.launch({
  browser: 'firefox',
  executablePath: '/usr/bin/firefox',
  headless: true,
})
const deadline = setTimeout(() => void browser.close(), 100000)
const errors = []
try {
  const page = await browser.newPage()
  page.on('pageerror', (error) => errors.push(error.message))
  page.setDefaultTimeout(15000)
  await page.setViewport({ width: 1440, height: 1000 })
  async function button(text) {
    console.log('button', text)
    await page.waitForFunction(
      (t) =>
        [...document.querySelectorAll('button')].some(
          (b) => b.textContent.trim() === t && !b.disabled,
        ),
      {},
      text,
    )
    for (const node of await page.$$('button')) {
      if (await node.evaluate((el, t) => el.textContent.trim() === t, text)) {
        await node.evaluate((el) => el.scrollIntoView({ block: 'center' }))
        await page.waitForFunction(
          (el) => {
            const r = el.getBoundingClientRect()
            const h = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2)
            return h === el || el.contains(h)
          },
          {},
          node,
        )
        await node.click()
        return
      }
    }
    throw new Error('Missing button ' + text)
  }
  async function has(text) {
    await page.waitForFunction((t) => document.body.textContent.includes(t), {}, text)
  }
  async function confirm() {
    await page.$eval('dialog input[type="checkbox"]', (el) =>
      el.scrollIntoView({ block: 'center' }),
    )
    await page.locator('dialog input[type="checkbox"]').click()
    console.log(
      'confirmation',
      await page.$eval('dialog input[type="checkbox"]', (el) => ({
        checked: el.checked,
        disabled: el.disabled,
      })),
    )
  }
  await page.goto(origin)
  await page.locator('input[autocomplete="username"]').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await button('Entrar no workspace')
  await has('Visão geral')
  await page.goto(origin + '/#labs')
  await button('Revisar coleta Wazuh')
  await page.waitForSelector('dialog select')
  await page.select('dialog select', 'offline-reviewed')
  await has('Política proposta pela implantação')
  await page
    .locator('dialog textarea')
    .fill('Offline profile, agent, rule and limits reviewed; TLS loopback fixture only.')
  await confirm()
  await button('Registrar revisão')
  await has('Revisado · não verificado')
  await page.waitForSelector('dialog input[type="checkbox"]')
  assert.equal(await page.$eval('dialog input[type="checkbox"]', (el) => el.checked), false)
  await confirm()
  await button('Testar conexão revisada')
  await has('Transporte respondeu ao diagnóstico pontual.')
  assert.equal(await page.$eval('dialog input[type="checkbox"]', (el) => el.checked), false)
  assert.equal(
    await page.$eval('body', (el) => el.textContent.includes('untrusted-upstream-text')),
    false,
  )
  await page.$eval('dialog', (el) => {
    el.scrollTop = el.scrollHeight
  })
  await page.screenshot({ path: output + '/profiles-desktop.png', fullPage: false })
  await page.setViewport({ width: 390, height: 844 })
  await page.$eval('dialog', (el) => {
    el.scrollTop = el.scrollHeight
  })
  assert.ok(
    await page.$eval('dialog', (el) => el.scrollWidth <= el.clientWidth + 2),
    'Mobile dialog overflow',
  )
  await page.screenshot({ path: output + '/profiles-mobile.png', fullPage: false })
  await confirm()
  await button('Remover vínculo')
  await has('Sem vínculo')
  const state = await page.evaluate(async (id) => {
    const response = await fetch('/api/v1/labs/' + id + '/wazuh-binding')
    return response.json()
  }, lab_id)
  assert.equal(state.binding, null)
  assert.equal(state.status, 'unbound')
  assert.equal(errors.length, 0, errors.join('\n'))
  await writeFile(
    output + '/browser-summary.json',
    JSON.stringify(
      {
        screenshots: 2,
        js_errors: errors.length,
        reviewed: true,
        diagnosed: true,
        disabled: true,
        credentials_in_form: false,
      },
      null,
      2,
    ),
  )
} finally {
  clearTimeout(deadline)
  await browser.close()
}
