import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { NoticeContext } from './lib'
import { WazuhBinding, type WazuhBindingState } from './WazuhBinding'
import type { Lab, User } from './types'

const lab: Lab = {
  id: 'linux',
  name: 'Linux Lab',
  kind: 'linux',
  synthetic: false,
  authorized: false,
  active_run_id: null,
  description: '',
  owner: 'Lab owner',
  environment_version: 1,
  isolation: 'Isolado',
  connection_status: 'disconnected',
  execution_capability: 'linux-marker-only',
}
const admin: User = { id: 'admin', username: 'reviewer', role: 'administrator', active: true }
const state: WazuhBindingState = {
  status: 'unbound',
  configuration_available: true,
  proposed_policy: { agent_id: '007', expected_rule: '100200', ingestion_wait_seconds: 10 },
  binding: null,
  limitation: 'Revisão não comprova conectividade nem detecção.',
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
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})
function mount(
  value: typeof state,
  user = admin,
  environment = lab,
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
) {
  const fetcher = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => value })
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider client={cache}>
      <NoticeContext.Provider value={vi.fn()}>
        <WazuhBinding lab={environment} user={user} onClose={vi.fn()} />
      </NoticeContext.Provider>
    </QueryClientProvider>,
  )
  return fetcher
}

it('shows disconnected preparation honestly and disables review without deployment policy', async () => {
  mount({ ...state, configuration_available: false, proposed_policy: null })
  expect(await screen.findByText(/Política Wazuh válida.*não está disponível/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
  expect(screen.queryByLabelText(/URL|Senha|Token|Comando/)).not.toBeInTheDocument()
})

it('submits only reviewed scope confirmation without a URL or credentials', async () => {
  const fetcher = mount(state)
  await screen.findByText(/Política proposta pela implantação/)
  await userEvent.type(
    screen.getByLabelText('Revisão do mapeamento e escopo'),
    'Agente e regra de laboratório revisados, conta somente leitura e isolamento conferidos.',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Registrar revisão' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'PUT')).toBe(true),
  )
  const [, options] = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')!
  expect(Object.keys(JSON.parse(options.body)).sort()).toEqual([
    'confirm_read_only_scope',
    'review',
  ])
  expect(JSON.parse(options.body).confirm_read_only_scope).toBe(true)
})

it('viewers can inspect policy but cannot change bindings', async () => {
  mount(state, { ...admin, role: 'viewer' })
  await screen.findByText(/Política proposta pela implantação/)
  expect(screen.queryByRole('button', { name: 'Registrar revisão' })).not.toBeInTheDocument()
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
})

it('requires revoked and unreserved laboratory before changing bindings', async () => {
  mount(state, admin, { ...lab, authorized: true })
  await screen.findByText(/Política proposta pela implantação/)
  expect(screen.getByRole('checkbox')).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
})

const profiles: WazuhBindingState = {
  ...state,
  profiles_enabled: true,
  profiles: [
    {
      id: 'reviewed-one',
      revision: 1,
      available: true,
      configuration_hash: 'a'.repeat(64),
      policy: { agent_id: '007' },
    },
    {
      id: 'reviewed-two',
      revision: 2,
      available: true,
      configuration_hash: 'b'.repeat(64),
      policy: { agent_id: '008' },
    },
    { id: 'missing-secret', revision: 1, available: false, configuration_hash: null, policy: null },
  ],
}

it('selects known profile and exact hash; switching resets consent and draft', async () => {
  const fetcher = mount(profiles)
  const select = await screen.findByLabelText('Perfil defensivo conhecido')
  expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
  await userEvent.selectOptions(select, 'reviewed-one')
  await userEvent.type(
    screen.getByLabelText('Revisão do mapeamento e escopo'),
    'First profile reviewed only in this offline fixture.',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.selectOptions(select, 'reviewed-two')
  expect(screen.getByRole('checkbox')).not.toBeChecked()
  expect(screen.getByLabelText('Revisão do mapeamento e escopo')).toHaveValue('')
  await userEvent.type(
    screen.getByLabelText('Revisão do mapeamento e escopo'),
    'Second profile reviewed only in this offline fixture.',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Registrar revisão' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'PUT')).toBe(true),
  )
  const [, options] = fetcher.mock.calls.find(([, options]) => options?.method === 'PUT')!
  expect(JSON.parse(options.body)).toMatchObject({
    profile_id: 'reviewed-two',
    confirm_configuration_hash: 'b'.repeat(64),
  })
})

it('refetch loading and failure discard prior consent even when cached data exists', async () => {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const fetcher = mount(profiles, admin, lab, cache)
  await userEvent.selectOptions(
    await screen.findByLabelText('Perfil defensivo conhecido'),
    'reviewed-one',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  let reject!: (error: Error) => void
  fetcher.mockImplementationOnce(
    () =>
      new Promise((_, fail) => {
        reject = fail
      }),
  )
  let pending!: Promise<void>
  act(() => {
    pending = cache.invalidateQueries()
  })
  await screen.findByText(/Carregando dados/)
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  fetcher.mockRejectedValue(new Error('Offline failure'))
  act(() => {
    reject(new Error('Offline failure'))
  })
  expect(await screen.findByRole('alert', {}, { timeout: 3000 })).toHaveTextContent(
    'Offline failure',
  )
  await pending
  expect(screen.queryByRole('button', { name: 'Registrar revisão' })).not.toBeInTheDocument()
})

it.each(['unavailable', 'stale', 'reachable'] as const)(
  'shows sanitized %s diagnostic with no event count inference',
  async (status) => {
    const binding = {
      agent_id: '007',
      expected_rule: '100200',
      configuration_hash: 'a'.repeat(64),
      review: 'Reviewed offline fixture',
    }
    const value = { ...profiles, status: 'reviewed_unverified', binding }
    const fetcher = mount(value)
    await screen.findByText('Reviewed offline fixture')
    fetcher.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        status,
        configuration_hash: binding.configuration_hash,
        checked_at: '2026-11-27T12:00:00Z',
        events_queried: false,
        limitation: 'No ingestion or detection inferred.',
      }),
    })
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(screen.getByRole('button', { name: 'Testar conexão revisada' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      status === 'unavailable'
        ? 'quantidade de eventos desconhecida'
        : status === 'stale'
          ? 'resultado descartado'
          : 'diagnóstico pontual',
    )
    expect(screen.getByRole('checkbox')).not.toBeChecked()
  },
)
