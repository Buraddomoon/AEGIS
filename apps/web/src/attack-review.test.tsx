import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AttackReview } from './AttackReview'

const identity = 'a'.repeat(64)
const candidate = 'b'.repeat(64)
const item = { plan_sha256: identity, candidate_id: candidate, candidate_version: '20.0' }
const page = (items: unknown[], total = items.length) => ({ items, total, offset: 0, limit: 20 })
const plan = {
  ...item,
  source_commit: 'c'.repeat(40),
  source_sha256: 'd'.repeat(64),
  license_sha256: 'e'.repeat(64),
  source_url: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/pinned.json',
  provenance: 'official_commit',
  base_release_id: 'f'.repeat(64),
  database_scope: { host: 'localhost', port: 18782, database: 'aegis', schema: 'disposable' },
  publication_status: 'not_applied',
  blockers: [] as string[],
  counts: {
    active: 1,
    added: 0,
    changed: 0,
    absent: 1,
    pending_runs: 0,
    reservations: 0,
    resumable_schedules: 0,
  },
  changes: page([
    {
      id: 'T1059.004',
      name: '<script>unsafe()</script>',
      kind: 'absent',
      fields: ['present_in_current'],
      before: { present_in_current: true },
      after: { present_in_current: false },
    },
  ]),
  tests_requiring_review: page([
    { id: 'demo-shell', version: 1, technique_id: 'T1059.004', approved: true },
  ]),
  test_reference_count: 3,
  authorization_policy: 'Escopos anteriores exigem nova revisão; histórico preservado.',
}
const instruction = {
  plan_sha256: identity,
  candidate_id: candidate,
  status: 'host_only_not_applied',
  command: `python scripts/update_attack.py apply ${candidate} --confirm-plan ${identity} --actor uuid`,
  limitation: 'Credencial SQL de implantação e destino revisado exigidos.',
}
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
const refused = {
  ok: false,
  status: 409,
  json: async () => ({ error: { message: 'Plano mudou; gere outro no host.' } }),
}
function mock(detail = plan, confirmation: () => unknown = () => ok(instruction)) {
  const fetch = vi.fn(async (url: string, _options?: RequestInit) => {
    if (url.endsWith('/instruction')) return confirmation()
    if (url.includes('/reviews?')) return ok({ ...page([item]), status: 'available' })
    return ok(detail)
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <AttackReview />
    </QueryClientProvider>,
  )
  return client
}
async function open() {
  await userEvent.click(screen.getByRole('button', { name: 'Revisar atualização ATT&CK' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Inspecionar plano' }))
  await screen.findByRole('region', { name: 'Plano ATT&CK revalidado' })
}
async function confirm() {
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Validar instrução local' }))
}
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute('open', '')
  }
  HTMLDialogElement.prototype.close = function () {
    this.removeAttribute('open')
  }
})
afterEach(() => {
  cleanup()
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
  vi.unstubAllGlobals()
})

it('requires explicit review and fresh server confirmation of the exact hashes without publishing', async () => {
  const fetch = mock()
  mount()
  await open()
  expect(screen.getByRole('button', { name: 'Validar instrução local' })).toBeDisabled()
  expect(screen.getByText('localhost:18782/aegis · schema disposable')).toBeInTheDocument()
  expect(screen.getByText(/demo-shell v1/)).toBeInTheDocument()
  expect(screen.getByText(/Absência|Ausência/)).toBeInTheDocument()
  await userEvent.click(screen.getByText(/<script>unsafe/))
  expect(screen.getByText('true')).toBeInTheDocument()
  expect(screen.getByText('false')).toBeInTheDocument()
  expect(document.querySelector('script')).toBeNull()
  await confirm()
  expect(await screen.findByText(instruction.command)).toBeInTheDocument()
  expect(screen.getByText(/publicação ainda não aplicada/)).toBeInTheDocument()
  expect(fetch.mock.calls.every(([, options]) => !options?.method)).toBe(true)
})

it.each(['disabled', 'empty'])('shows %s inventory honestly', async (state) => {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue(ok({ ...page([]), status: state === 'disabled' ? state : 'available' })),
  )
  mount()
  await userEvent.click(screen.getByRole('button', { name: 'Revisar atualização ATT&CK' }))
  expect(
    await screen.findByText(
      state === 'disabled'
        ? 'Revisão web desabilitada nesta implantação'
        : 'Nenhum plano preparado',
    ),
  ).toBeInTheDocument()
  expect(screen.queryByRole('checkbox')).toBeNull()
})

it.each(['blocked', 'already_applied'])('refuses confirmation for %s plans', async (state) => {
  mock({
    ...plan,
    blockers: state === 'blocked' ? ['license_review_required'] : [],
    publication_status: state === 'already_applied' ? state : 'not_applied',
  })
  mount()
  await open()
  expect(screen.getByRole('checkbox')).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Validar instrução local' })).toBeDisabled()
  if (state === 'blocked')
    expect(screen.getByText('Licença exige revisão no repositório')).toBeInTheDocument()
  else expect(screen.getByText(/Já aplicado/)).toBeInTheDocument()
})

it('discards confirmation on server drift and requires a new review', async () => {
  mock(plan, () => refused)
  mount()
  await open()
  await confirm()
  expect(await screen.findByText('Plano mudou; gere outro no host.')).toBeInTheDocument()
  expect(screen.getByRole('checkbox')).not.toBeChecked()
  expect(screen.getByRole('button', { name: 'Validar instrução local' })).toBeDisabled()
  expect(screen.queryByText(instruction.command)).toBeNull()
})

it('refuses confirmation response for another artifact', async () => {
  mock(plan, () => ok({ ...instruction, candidate_id: '0'.repeat(64) }))
  mount()
  await open()
  await confirm()
  expect(await screen.findByText(/Confirmação diverge do artefato/)).toBeInTheDocument()
  expect(screen.queryByText(instruction.command)).toBeNull()
})

it('rejects cached detail for another plan identity', async () => {
  mock({ ...plan, plan_sha256: '0'.repeat(64) })
  mount()
  await userEvent.click(screen.getByRole('button', { name: 'Revisar atualização ATT&CK' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Inspecionar plano' }))
  expect(await screen.findByText(/Identidade do plano divergente/)).toBeInTheDocument()
  expect(screen.queryByRole('checkbox')).toBeNull()
})

it('clears confirmation while detail refetch is pending and after a failed refresh', async () => {
  const fetch = mock()
  const client = mount()
  await open()
  await confirm()
  await screen.findByText(instruction.command)
  let resolve: (value: unknown) => void = () => {}
  fetch.mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done
      }),
  )
  void client.invalidateQueries({ queryKey: ['/catalog/attack/reviews', identity] })
  await waitFor(() => expect(screen.queryByRole('checkbox')).toBeNull())
  expect(screen.queryByText(instruction.command)).toBeNull()
  resolve(refused)
  await screen.findByText('Plano mudou; gere outro no host.')
  expect(screen.queryByRole('checkbox')).toBeNull()
})

it('ignores late instruction after switching away and resets pagination confirmation', async () => {
  let resolve: (value: unknown) => void = () => {}
  const fetch = mock(
    { ...plan, changes: { ...plan.changes, total: 21 } },
    () =>
      new Promise((done) => {
        resolve = done
      }),
  )
  mount()
  await open()
  await confirm()
  await userEvent.click(screen.getByRole('button', { name: 'Próxima · mudanças' }))
  await screen.findByRole('checkbox')
  resolve(ok(instruction))
  await waitFor(() => expect(screen.queryByText(instruction.command)).toBeNull())
  expect(screen.getByRole('checkbox')).not.toBeChecked()
  expect(fetch.mock.calls.some(([url]) => url.includes('offset=20&test_offset=0'))).toBe(true)
})
