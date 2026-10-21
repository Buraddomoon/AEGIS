import { cleanup, render, screen, waitFor } from '@testing-library/react'
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
function mount(value: typeof state, user = admin, environment = lab) {
  const fetcher = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => value })
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
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
