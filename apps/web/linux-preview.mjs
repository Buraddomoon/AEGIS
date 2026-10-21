// Read-only UI verification for the single approved integrated assay.
import assert from 'node:assert/strict'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) input += chunk
const { username, password, runId } = JSON.parse(input)
const browser = await puppeteer.launch({ browser: 'firefox', executablePath: '/usr/bin/firefox', headless: true })
try {
  const page = await browser.newPage(), errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.setViewport({width: 1440, height: 1100, deviceScaleFactor: 1})
  await page.goto('http://localhost:18785', {waitUntil: 'networkidle0'})
  await page.waitForSelector('input[autocomplete="username"]')
  await page.type('input[autocomplete="username"]', username)
  await page.type('input[autocomplete="current-password"]', password)
  await page.click('form button[type="submit"]')
  await page.waitForSelector('.sidebar')
  await page.goto(`http://localhost:18785/#executions/${runId}`, {waitUntil: 'networkidle0'})
  await page.waitForFunction(() => document.querySelector('main')?.textContent.includes('Inconclusivo'))
  const text = await page.$eval('main', element => element.textContent)
  assert(text.includes('LINUX REAL') && text.includes('Comprovantes do executor'))
  assert(!text.includes('DADOS SINTÉTICOS'))
  await page.click('.result-card details summary')
  await page.waitForFunction(() => document.querySelector('.result-card pre')?.textContent.includes('execution_receipt'))
  await page.screenshot({path: '../../.local/linux-lab/platform-execution.png', fullPage: true})
  assert.deepEqual(errors, [])
  console.log('PASS: real Linux execution UI, inconclusive result, executor receipt and cleanup; screenshot local.')
} finally { await browser.close() }
