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
  await screen.findByText(campaign.name)
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
