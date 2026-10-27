import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { BindingReview, type BindingReviewState } from './BindingReview'
import { Laboratories } from './Management'
import type { Lab, User } from './types'

const lab: Lab = {
  id: 'linux',
  name: 'Linux Lab',
  kind: 'linux',
  synthetic: false,
  authorized: false,
  active_run_id: null,
  description: '',
  owner: 'Responsável',
  environment_version: 2,
  isolation: 'Isolado',
  connection_status: 'disconnected',
  execution_capability: 'disabled',
}
const admin: User = { id: 'admin', username: 'reviewer', role: 'administrator', active: true }
const ready: BindingReviewState = {
  format: 'aegis-linux-binding-review/1',
  laboratory_id: lab.id,
  environment_version: 2,
  reviewed_at: '2026-10-27T12:00:00+00:00',
  status: 'persisted_prerequisites_satisfied',
  blockers: [],
  nonterminal_runs: 0,
  nonterminal_tests: 0,
  dispatches_examined: 1,
  dispatch_history_complete: true,
  unconfirmed_cleanup_count: 0,
  unconfirmed_execution_ids: [],
  unconfirmed_sample_truncated: false,
  runner_contacted: false,
  journal_verified: false,
  activation_permitted: false,
  normal_operation_permitted: false,
}
function response(value: unknown) {
  return { ok: true, status: 200, json: async () => value }
}
function mount(component: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return render(<QueryClientProvider client={client}>{component}</QueryClientProvider>)
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

it('shows actual blockers, counts and incomplete sample without offering activation', async () => {
  const fetcher = vi.fn().mockResolvedValue(
    response({
      ...ready,
      status: 'blocked',
      blockers: ['nonterminal_runs', 'unconfirmed_cleanup', 'dispatch_history_limit'],
      nonterminal_runs: 2,
      unconfirmed_cleanup_count: 1,
      dispatch_history_complete: false,
      unconfirmed_execution_ids: ['test-original'],
      unconfirmed_sample_truncated: true,
    }),
  )
  vi.stubGlobal('fetch', fetcher)
  mount(<BindingReview lab={lab} onClose={vi.fn()} />)
  expect(await screen.findByText('Revisão do vínculo bloqueada.')).toBeInTheDocument()
  expect(screen.getByText(/Há solicitações ou execuções/)).toBeInTheDocument()
  expect(screen.getByText('test-original')).toBeInTheDocument()
  expect(screen.getByText(/Amostra limitada/)).toBeInTheDocument()
  expect(screen.getByText(/Incompleto; nenhuma liberação/)).toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: /Ativar|Autorizar|Liberar|Executar/ }),
  ).not.toBeInTheDocument()
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/labs/linux/binding-review')
  expect(fetcher.mock.calls[0][1].method).toBeUndefined()
})

it('labels successful persisted review as insufficient to authorize activation', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(ready)))
  mount(<BindingReview lab={lab} onClose={vi.fn()} />)
  expect(await screen.findByText(/Pré-requisitos persistidos atendidos/)).toHaveTextContent(
    /continua sem autorização/,
  )
  expect(screen.getByText(/não verifica o diário/)).toBeInTheDocument()
})

it.each([
  { laboratory_id: 'other' },
  { environment_version: 1 },
  { activation_permitted: true },
  { runner_contacted: true },
  { nonterminal_tests: 1 },
  { dispatch_history_complete: false },
  { reviewed_at: 'invalid' },
  { unconfirmed_execution_ids: null },
])('refuses incompatible or contradictory API context %j', async (change) => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ...ready, ...change })))
  mount(<BindingReview lab={lab} onClose={vi.fn()} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Revisão incompatível')
  expect(screen.queryByText(/Pré-requisitos persistidos atendidos/)).not.toBeInTheDocument()
})

it('hides a previous successful snapshot after a refresh fails', async () => {
  const fetcher = vi.fn().mockResolvedValue(response(ready))
  vi.stubGlobal('fetch', fetcher)
  mount(<BindingReview lab={lab} onClose={vi.fn()} />)
  await screen.findByText(/Pré-requisitos persistidos atendidos/)
  fetcher.mockResolvedValue({
    ok: false,
    status: 503,
    json: async () => ({ error: { message: 'Revisão indisponível' } }),
  })
  await userEvent.click(screen.getByRole('button', { name: 'Atualizar revisão' }))
  expect(screen.queryByText(/Pré-requisitos persistidos atendidos/)).not.toBeInTheDocument()
  expect(await screen.findByRole('alert', {}, { timeout: 4000 })).toHaveTextContent(
    'Revisão indisponível',
  )
})

it.each(['administrator', 'viewer'] as const)(
  'offers the administrative review only to %s as appropriate',
  async (role) => {
    const fetcher = vi.fn(async (url: string) =>
      response(url.endsWith('/binding-review') ? ready : { items: [lab] }),
    )
    vi.stubGlobal('fetch', fetcher)
    mount(<Laboratories user={{ ...admin, role }} />)
    await screen.findByRole('heading', { name: lab.name })
    const button = screen.queryByRole('button', { name: 'Revisar pendências do vínculo' })
    if (role === 'administrator') {
      expect(button).toBeInTheDocument()
      await userEvent.click(button!)
      await screen.findByRole('heading', { name: 'Pendências do vínculo Linux' })
      await waitFor(() =>
        expect(fetcher.mock.calls.some(([url]) => url.endsWith('/binding-review'))).toBe(true),
      )
    } else {
      expect(button).not.toBeInTheDocument()
      expect(fetcher.mock.calls.some(([url]) => url.endsWith('/binding-review'))).toBe(false)
    }
  },
)
