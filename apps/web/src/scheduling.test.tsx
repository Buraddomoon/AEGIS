import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NoticeContext } from './lib'
import { ScheduleForm, Scheduling } from './Scheduling'

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
function wrap(child: React.ReactNode, notify = vi.fn()) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <NoticeContext.Provider value={notify}>{child}</NoticeContext.Provider>
    </QueryClientProvider>,
  )
}
const campaign = { id: 'demo-campaign', name: 'Campanha de teste' }
it('keeps failed plans open and reports the API error without authorizing anything', async () => {
  const close = vi.fn(),
    notify = vi.fn()
  const fetcher = vi.fn().mockImplementation(async (_path, options) =>
    options?.method === 'POST'
      ? {
          ok: false,
          status: 409,
          json: async () => ({ error: { message: 'Laboratório revogado' } }),
        }
      : { ok: true, status: 200, json: async () => ({ items: [campaign], total: 1 }) },
  )
  vi.stubGlobal('fetch', fetcher)
  wrap(<ScheduleForm onClose={close} />, notify)
  await screen.findByRole('option', { name: /Campanha de teste/ })
  await userEvent.selectOptions(screen.getByLabelText('Campanha'), campaign.id)
  await userEvent.click(screen.getByRole('button', { name: 'Criar plano' }))
  await waitFor(() => expect(notify).toHaveBeenCalledWith('Laboratório revogado', true))
  expect(close).not.toHaveBeenCalled()
  const posted = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')
  expect(posted).toHaveLength(1)
  const body = JSON.parse(posted[0][1].body)
  expect(body.max_occurrences).toBe(5)
  expect(body.starts_at).toMatch(/Z$/)
  expect(posted[0][0]).toBe('/api/v1/schedules')
})

it('requires explicit real intent before proposing a Linux schedule', async () => {
  const fetcher = vi.fn(async (path: string, options?: RequestInit) => {
    if (options?.method === 'POST')
      return {
        ok: false,
        status: 409,
        json: async () => ({ error: { message: 'Opt-in ausente' } }),
      }
    return {
      ok: true,
      status: 200,
      json: async () =>
        path.includes('/labs')
          ? { items: [{ id: 'lab-linux', kind: 'linux' }] }
          : { items: [{ ...campaign, laboratory_id: 'lab-linux' }] },
    }
  })
  vi.stubGlobal('fetch', fetcher)
  wrap(<ScheduleForm onClose={vi.fn()} />)
  await screen.findByRole('option', { name: /Linux real/ })
  await userEvent.selectOptions(screen.getByLabelText('Campanha'), campaign.id)
  expect(screen.getByRole('button', { name: 'Criar plano' })).toBeDisabled()
  await userEvent.click(screen.getByLabelText(/Estou propondo execuções reais/))
  await userEvent.click(screen.getByRole('button', { name: 'Criar plano' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(true),
  )
  const posted = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
  expect(JSON.parse(posted[1]!.body as string).confirm_real_execution).toBe(true)
})

const realSchedule = {
  id: 'schedule-real',
  campaign_id: 'campaign',
  laboratory_id: 'lab-linux',
  created_by: 'operator',
  state: 'PENDING_APPROVAL',
  plan_hash: 'a'.repeat(64),
  synthetic: false,
  starts_at: '2026-11-24T20:00:00Z',
  ends_at: '2026-11-24T21:00:00Z',
  interval_seconds: 60,
  max_duration_seconds: 30,
  max_occurrences: 2,
  occurrences_count: 0,
  scope: {
    mode: 'linux',
    synthetic: false,
    environment_version: 1,
    asset_id: 'reviewed-asset',
    rule_versions: {},
    test_definitions: [{ name: 'Marcador benigno', version: 1 }],
  },
  plan: { version: 'aegis-linux-schedule/1', max_concurrency: 1 },
  authorizations: [],
}
function realView(creator = 'operator', synthetic = false) {
  const fetcher = vi.fn(async (path: string, _options?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () =>
      path === '/api/v1/schedules/schedule-real'
        ? { ...realSchedule, created_by: creator, synthetic }
        : { items: [], total: 0, schedule_id: 'schedule-real' },
  }))
  vi.stubGlobal('fetch', fetcher)
  wrap(
    <Scheduling
      id="schedule-real"
      user={{ id: 'administrator', username: 'administrator', role: 'administrator', active: true }}
    />,
  )
  return fetcher
}

it('reviews real scope and exact remaining budget with segregated real confirmation', async () => {
  const fetcher = realView()
  await screen.findByText('LINUX REAL')
  expect(screen.getByText(/Ativo reviewed-asset/)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: /Revisar autorização recorrente/ }))
  expect(screen.getByText(/Restam até 2 horários/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Autorizar plano real' })).toBeDisabled()
  await userEvent.click(screen.getByLabelText(/Revisei ativo, teste, versões/))
  await userEvent.click(screen.getByRole('button', { name: 'Autorizar plano real' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(true),
  )
  const post = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!
  expect(post[0]).toBe('/api/v1/schedules/schedule-real/approve')
  expect(JSON.parse(post[1]!.body as string)).toEqual({
    confirm_plan_hash: 'a'.repeat(64),
    confirm_automatic_execution: true,
    confirm_real_execution: true,
  })
})

it('withholds self approval for a real plan and rejects contradictory origin', async () => {
  realView('administrator')
  await screen.findByText('Revisão exige outro administrador ativo.')
  expect(
    screen.queryByRole('button', { name: /Revisar autorização recorrente/ }),
  ).not.toBeInTheDocument()
  cleanup()
  realView('operator', true)
  await screen.findByText('Modo ou plano recebido não corresponde ao agendamento.')
  expect(
    screen.queryByRole('button', { name: /Revisar autorização recorrente/ }),
  ).not.toBeInTheDocument()
})
it('renders an empty list from the API and hides mutation controls from viewers', async () => {
  vi.stubGlobal(
    'fetch',
    vi
      .fn()
      .mockResolvedValue({ ok: true, status: 200, json: async () => ({ items: [], total: 0 }) }),
  )
  wrap(<Scheduling user={{ id: 'viewer', username: 'viewer', role: 'viewer', active: true }} />)
  await screen.findByText('Nenhum agendamento criado')
  expect(screen.queryByRole('button', { name: /Novo agendamento/ })).not.toBeInTheDocument()
  expect(screen.getByText(/Atrasos acima de 30 segundos/)).toBeInTheDocument()
})
