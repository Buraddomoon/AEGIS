// Native #104 browser client. No route interception, fixtures or direct marker execution.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, writeFile, readFile } from 'node:fs/promises'
import puppeteer from 'puppeteer-core'

let input = ''
for await (const chunk of process.stdin) {
  input += chunk
  assert(input.length <= 128 * 1024)
}
const { plan, package_sha256, accounts, proof_directory: output } = JSON.parse(input)
assert.equal(plan.occurrences, 2)
assert.equal(plan.test_id, 'linux-file-marker/v1')
assert.equal(plan.origin, 'http://192.168.253.12:8080')
const browser = await puppeteer.launch({
  browser: 'firefox',
  executablePath: '/usr/bin/firefox',
  headless: true,
})
const errors = []
const pages = []
await mkdir(output, { recursive: true })
async function button(page, label, selector = 'button') {
  await page.bringToFront()
  await page.waitForFunction(
    (label, selector) =>
      [...document.querySelectorAll(selector)].some(
        (e) => e.textContent.trim() === label && !e.disabled,
      ),
    { polling: 100 },
    label,
    selector,
  )
  for (const handle of await page.$$(selector)) {
    if (await handle.evaluate((e, value) => e.textContent.trim() === value, label)) {
      await handle.click()
      return
    }
  }
  throw new Error('fixed_button_unavailable')
}
async function visible(page, value) {
  await page.bringToFront()
  await page.waitForFunction(
    (value) => document.querySelector('main')?.textContent.includes(value),
    { polling: 100 },
    value,
  )
}
async function api(page, path, method = 'GET', body) {
  return page.evaluate(
    async (origin, path, method, body) => {
      const csrf =
        document.cookie
          .split('; ')
          .find((x) => x.startsWith('aegis_csrf='))
          ?.split('=')[1] ?? ''
      const response = await fetch(`${origin}/api/v1${path}`, {
        method,
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-Aegis-Request': 'browser',
          'X-CSRF-Token': csrf,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      })
      if (!response.ok) throw new Error(`native_api_${response.status}`)
      return response.status === 204 ? null : response.json()
    },
    plan.origin,
    path,
    method,
    body,
  )
}
async function login(role) {
  const context = await browser.createBrowserContext()
  const page = await context.newPage()
  pages.push(page)
  page.on('pageerror', () => errors.push('browser_error'))
  page.setDefaultTimeout(25000)
  await page.setViewport({ width: 1440, height: 1100, deviceScaleFactor: 1 })
  await page.goto(plan.origin, { waitUntil: 'networkidle0' })
  try {
    await page.waitForSelector('input[autocomplete="username"]')
  } catch (error) {
    // Capture only the pre-login screen, before entering either password.
    await save(
      `login-${role}-failure.json`,
      JSON.stringify(
        {
          stage: 'before_credentials',
          url: page.url(),
          title: await page.title(),
          text: await page.evaluate(() => document.body.innerText.slice(0, 2000)),
          browser_errors: errors,
        },
        null,
        2,
      ),
    )
    await page.screenshot({ path: `${output}/login-${role}-failure.png`, fullPage: true })
    throw error
  }
  const account = accounts.find((x) => x.role === role)
  await page.type('input[autocomplete="username"]', account.username)
  await page.type('input[autocomplete="current-password"]', account.password)
  await button(page, 'Entrar no workspace')
  await visible(page, 'Visão geral')
  return page
}
async function save(name, bytes) {
  await writeFile(`${output}/${name}`, bytes)
  return createHash('sha256').update(bytes).digest('hex')
}
async function download(page, path, name) {
  const data = await page.evaluate(
    async (origin, path) => {
      const response = await fetch(`${origin}/api/v1${path}`)
      if (!response.ok) throw new Error('native_export_failed')
      return Array.from(new Uint8Array(await response.arrayBuffer()))
    },
    plan.origin,
    path,
  )
  const bytes = Buffer.from(data)
  if (name.endsWith('.pdf')) assert.equal(bytes.subarray(0, 5).toString(), '%PDF-')
  return save(name, bytes)
}
try {
  const admin = await login('administrator')
  const lab = await api(admin, '/labs/linux/register', 'POST', {
    name: `Scheduling104 ${plan.workflow_run}`,
    owner: 'Bounded native issue104',
    isolation_review:
      'Fresh hosted VM, dedicated immutable images, two private networks, no original mounts, UID10001, read-only runner and tmpfs marker; reviewed native package ' +
      package_sha256,
    confirm_isolation_review: true,
  })
  assert.equal(lab.id, plan.identity.laboratory_id)
  const preflight = await api(admin, `/labs/${lab.id}/preflight`, 'POST', { confirm: true })
  assert.equal(preflight.success, true)
  await api(admin, `/labs/${lab.id}/authorization`, 'PATCH', { authorized: true })
  const operator = await login('operator')
  const requester = await api(operator, '/auth/me')
  const reviewer = await api(admin, '/auth/me')
  assert.notEqual(requester.id, reviewer.id)
  const campaign = await api(operator, '/campaigns', 'POST', {
    name: 'Native recurring marker104',
    objective: 'Two bounded real markers; no SIEM or ATT&CK efficacy claim.',
    laboratory_id: lab.id,
    test_ids: [plan.definition_id],
  })
  // API setup bypasses useAction's query invalidation. Load a fresh document so
  // the overview's cached empty campaign list cannot mask the new campaign.
  await operator.goto(`${plan.origin}/#schedules`, { waitUntil: 'networkidle0' })
  await button(operator, 'Novo agendamento')
  await operator.waitForFunction(
    (id) =>
      [...document.querySelectorAll('dialog select option')].some(
        (e) => e.value === id && e.textContent.includes('Linux real'),
      ),
    { polling: 100 },
    campaign.id,
  )
  await operator.select('dialog select', campaign.id)
  await operator.click('dialog input[type="checkbox"]')
  const requestedAt = Date.now()
  const start = requestedAt + 25000
  const end = requestedAt + 180000
  assert(end < Date.parse(plan.expires_at))
  await operator.evaluate(
    (start, end) => {
      const format = (ms) => {
        const d = new Date(ms)
        return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19)
      }
      const fields = [...document.querySelectorAll('dialog input:not([type="checkbox"])')]
      const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set
      for (const [field, value] of [
        [fields[0], format(start)],
        [fields[1], format(end)],
        [fields[2], '60'],
        [fields[3], '2'],
        [fields[4], '30'],
      ]) {
        set.call(field, value)
        field.dispatchEvent(new Event('input', { bubbles: true }))
        field.dispatchEvent(new Event('change', { bubbles: true }))
      }
    },
    start,
    end,
  )
  await button(operator, 'Criar plano', 'dialog button')
  await operator.waitForFunction(() => !document.querySelector('dialog[open]'), { polling: 100 })
  const id = await operator.evaluate(() => location.hash.split('/')[1])
  const schedule = await api(operator, `/schedules/${id}`)
  assert.equal(schedule.synthetic, false)
  assert.equal(schedule.max_occurrences, 2)
  assert.equal(schedule.max_duration_seconds, 30)
  assert.equal(schedule.interval_seconds, 60)
  assert.equal(schedule.scope.asset_id, plan.identity.asset_id)
  assert.equal(schedule.created_by, requester.id)
  await save('schedule-proposed.json', JSON.stringify(schedule, null, 2))
  await admin.evaluate((id) => {
    location.hash = `schedules/${id}`
  }, id)
  await visible(admin, 'LINUX REAL')
  await button(admin, 'Revisar autorização recorrente')
  await admin.click('dialog input[type="checkbox"]')
  await admin.screenshot({ path: `${output}/approval.png`, fullPage: true })
  await button(admin, 'Autorizar plano real', 'dialog button')
  await admin.waitForFunction(() => !document.querySelector('dialog[open]'), { polling: 100 })
  await admin.waitForFunction(
    async (id) => {
      const schedule = await (await fetch(`/api/v1/schedules/${id}`)).json()
      const rows = await (await fetch(`/api/v1/schedules/${id}/occurrences`)).json()
      if (schedule.state === 'INVALIDATED' || rows.items.some((x) => x.status !== 'QUEUED'))
        throw new Error('native_occurrence_not_issued')
      if (rows.items.length !== 2) return false
      const runs = await Promise.all(
        rows.items.map(async (x) => (await fetch(`/api/v1/executions/${x.run_id}`)).json()),
      )
      return runs.every((run) => run.state === 'COMPLETED')
    },
    { polling: 1000, timeout: 150000 },
    id,
  )
  const occurrences = (await api(admin, `/schedules/${id}/occurrences`)).items.sort((a, b) =>
    a.scheduled_for.localeCompare(b.scheduled_for),
  )
  assert.equal(occurrences.length, 2)
  assert.equal(new Set(occurrences.map((x) => x.authorization_id)).size, 1)
  assert.equal(
    Date.parse(occurrences[1].scheduled_for) - Date.parse(occurrences[0].scheduled_for),
    60000,
  )
  const runIds = []
  const hashes = {}
  for (const occurrence of occurrences) {
    const run = await api(admin, `/executions/${occurrence.run_id}`)
    runIds.push(run.id)
    assert.equal(run.synthetic, false)
    assert.equal(run.scope.mode, 'linux')
    assert.equal(run.requested_by, requester.id)
    assert.equal(run.approval.approved_by, reviewer.id)
    assert.equal(run.approval.schedule_authorization_id, occurrence.authorization_id)
    assert.equal(run.executions.length, 1)
    const item = run.executions[0]
    assert.equal(item.synthetic, false)
    assert.equal(item.executed, true)
    assert.equal(item.result.outcome, 'INCONCLUSIVE')
    assert.equal(item.result.synthetic, false)
    assert.equal(item.events.length, 0)
    assert.equal(item.evidence.length, 0)
    assert.equal(item.runner_receipt.content.artifact_bytes, 43)
    assert.equal(item.runner_receipt.content.synthetic, false)
    assert.equal(item.runner_cleanup.content.cleanup_state, 'CLEANED')
    assert.equal(item.runner_dispatch.spec_hash, item.runner_cleanup.content.spec_hash)
    hashes[`execution-${run.id}.json`] = await save(
      `execution-${run.id}.json`,
      JSON.stringify(run, null, 2),
    )
  }
  await admin.waitForFunction(
    async (id) => {
      const result = await (await fetch(`/api/v1/schedules/${id}/reports`)).json()
      return (
        result.items.length === 2 &&
        result.items.every((r) => r.state === 'READY' && r.synthetic === false)
      )
    },
    { polling: 500, timeout: 15000 },
    id,
  )
  const reports = (await api(admin, `/schedules/${id}/reports`)).items
  assert.deepEqual(new Set(reports.map((x) => x.kind)), new Set(['BASELINE', 'COMPARISON']))
  for (const report of reports) {
    for (const format of ['json', 'html', 'pdf']) {
      const name = `snapshot-${report.id}.${format}`
      hashes[name] = await download(
        admin,
        `/schedules/${id}/reports/${report.id}?format=${format}&expected_sha256=${report.document_sha256}`,
        name,
      )
    }
    const document = JSON.parse(await readFile(`${output}/snapshot-${report.id}.json`, 'utf8'))
    assert.equal(document.synthetic, false)
    assert.equal(document.automation.policy_version, 'scheduled-linux-report/1')
  }
  await admin.bringToFront()
  await admin.screenshot({ path: `${output}/recurrence.png`, fullPage: true })
  await admin.setViewport({ width: 390, height: 844, deviceScaleFactor: 1 })
  await admin.waitForFunction(
    () => document.querySelector('.sidebar').getBoundingClientRect().right <= 0,
    { polling: 100 },
  )
  assert(await admin.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await admin.screenshot({ path: `${output}/recurrence-mobile.png`, fullPage: true })
  await api(admin, `/schedules/${id}/revoke`, 'POST', { confirm: true })
  await api(admin, `/labs/${lab.id}/authorization`, 'PATCH', { authorized: false })
  const final = await api(admin, `/schedules/${id}`)
  assert.equal(final.state, 'REVOKED')
  assert.equal(final.occurrences_count, 2)
  for (const report of reports) {
    const data = JSON.stringify(await api(admin, `/schedules/${id}/reports/${report.id}`))
    const previous = JSON.parse(await readFile(`${output}/snapshot-${report.id}.json`, 'utf8'))
    assert.deepEqual(JSON.parse(data), previous)
  }
  const allRuns = (await api(admin, '/executions?limit=100')).items
  assert.equal(allRuns.length, 2)
  assert(allRuns.every((run) => run.synthetic === false && runIds.includes(run.id)))
  assert.equal(errors.length, 0)
  await save(
    'browser.json',
    JSON.stringify(
      {
        status: 'NATIVE_RECURRENCE_VERIFIED',
        synthetic: false,
        package_sha256,
        schedule_id: id,
        plan_sha256: schedule.plan_hash,
        run_ids: runIds,
        occurrences: 2,
        receipts: 2,
        cleanups: 2,
        defensive_events: 0,
        expected_outcome: 'INCONCLUSIVE',
        snapshots: 2,
        pdf_exports: 2,
        browser_errors: 0,
        hashes,
      },
      null,
      2,
    ),
  )
} finally {
  await browser.close()
}
