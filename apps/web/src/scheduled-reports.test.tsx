import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { NoticeContext } from './lib'
import { ScheduledReports } from './ScheduledReports'
import type { ScheduledReport } from './types'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const report: ScheduledReport = {
  id: 'report-12345678',
  schedule_id: 'schedule-one',
  authorization_id: 'grant-current',
  occurrence_id: 'occurrence-one',
  run_id: 'run-current',
  previous_run_id: 'run-previous',
  kind: 'COMPARISON',
  state: 'READY',
  attempts: 1,
  next_attempt_at: '2026-11-09T12:00:00Z',
  error_code: null,
  document_sha256: 'a'.repeat(64),
  generated_at: '2026-11-09T12:00:00Z',
  synthetic: true,
}
const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data })
function mount(
  items: ScheduledReport[] = [report],
  returnedSchedule = 'schedule-one',
  downloadError = false,
) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 } } })
  const notify = vi.fn()
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  vi.stubGlobal(
    'URL',
    class extends URL {
      static createObjectURL = vi.fn(() => 'blob:pdf')
      static revokeObjectURL = vi.fn()
    },
  )
  const fetcher = vi.fn(async (path: string) =>
    path.includes('format=')
      ? downloadError
        ? {
            ok: false,
            status: 413,
            json: async () => ({ error: { message: 'Exporte JSON/HTML para este snapshot.' } }),
          }
        : {
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/pdf' }),
            blob: async () => new Blob(['%PDF-synthetic']),
          }
      : ok({ items, total: items.length, offset: 0, limit: 25, schedule_id: returnedSchedule }),
  )
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider client={client}>
      <NoticeContext.Provider value={notify}>
        <ScheduledReports scheduleId="schedule-one" />
      </NoticeContext.Provider>
    </QueryClientProvider>,
  )
  return { client, notify, fetcher, click }
}

it('shows frozen pair and downloads with exact schedule report and document hash', async () => {
  const { fetcher, click, notify } = mount()
  await screen.findByText('Comparação automática')
  expect(screen.getByText('Documento pronto')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Execução atual' })).toHaveAttribute(
    'href',
    '#executions/run-current',
  )
  expect(screen.getByRole('link', { name: 'Execução anterior' })).toHaveAttribute(
    'href',
    '#executions/run-previous',
  )
  await userEvent.click(screen.getByRole('button', { name: /Baixar PDF/ }))
  await waitFor(() => expect(click).toHaveBeenCalledOnce())
  expect(
    fetcher.mock.calls.some(
      ([path]) =>
        path ===
        `/api/v1/schedules/schedule-one/reports/report-12345678?format=pdf&expected_sha256=${'a'.repeat(64)}`,
    ),
  ).toBe(true)
  expect(notify).toHaveBeenCalledWith('Snapshot automático exportado.')
})

it('shows pending and failed requests without decorative download buttons', async () => {
  mount([
    {
      ...report,
      id: 'pending',
      kind: 'BASELINE',
      previous_run_id: null,
      state: 'PENDING',
      attempts: 0,
      document_sha256: null,
    },
    { ...report, id: 'failed', state: 'FAILED', error_code: 'SOURCE_LIMIT', document_sha256: null },
  ])
  await screen.findByText('Relatório inicial')
  expect(screen.getByText('Aguardando processamento')).toBeInTheDocument()
  expect(screen.getByText(/Documento excedeu o limite/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Baixar/ })).not.toBeInTheDocument()
})

it('explains historical schedules without a request and refuses mismatched cached context', async () => {
  const mounted = mount([])
  await screen.findByText('Nenhum relatório automático solicitado')
  expect(screen.getByText(/Somente ocorrências emitidas após/)).toBeInTheDocument()
  mounted.client.setQueryData(['/schedules/schedule-one/reports?limit=25&offset=0'], {
    items: [report],
    total: 1,
    schedule_id: 'another-schedule',
  })
  await screen.findByText('A lista recebida não corresponde ao agendamento selecionado.')
  expect(screen.queryByRole('button', { name: /Baixar/ })).not.toBeInTheDocument()
})

it('hides cached export controls after refresh failure', async () => {
  const { client, fetcher } = mount()
  await screen.findByRole('button', { name: /Baixar PDF/ })
  fetcher.mockResolvedValue({
    ok: false,
    status: 503,
    json: async () => ({ error: { message: 'Consulta indisponível' } }),
  })
  await client.refetchQueries()
  await screen.findByText('Consulta indisponível')
  expect(screen.queryByRole('button', { name: /Baixar/ })).not.toBeInTheDocument()
})

it('reports export errors and keeps the document available in other formats', async () => {
  const { notify, click } = mount([report], 'schedule-one', true)
  await screen.findByText('Comparação automática')
  await userEvent.click(screen.getByRole('button', { name: /Baixar PDF/ }))
  await waitFor(() =>
    expect(notify).toHaveBeenCalledWith('Exporte JSON/HTML para este snapshot.', true),
  )
  expect(click).not.toHaveBeenCalled()
  expect(screen.getByRole('button', { name: /Baixar JSON/ })).toBeEnabled()
})
