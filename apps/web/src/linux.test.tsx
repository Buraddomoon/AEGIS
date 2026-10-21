import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { NoticeContext } from './lib'
import { ExecutionDetail, Campaigns } from './Operations'
import { LinuxRegistration } from './LinuxRegistration'
import { Catalog } from './Catalog'

const administrator = {
  id: 'admin',
  username: 'reviewer',
  role: 'administrator' as const,
  active: true,
}
const detail = {
  id: 'run',
  campaign_id: 'campaign',
  campaign_name: 'Linux autorizado',
  objective: 'Marcador benigno',
  state: 'PENDING_APPROVAL',
  synthetic: false,
  requested_by: 'operator',
  scope_hash: 'a'.repeat(64),
  created_at: null,
  started_at: null,
  ended_at: null,
  approval: null,
  executions: [],
  steps: [],
  scope: {
    mode: 'linux',
    environment_version: 1,
    test_definitions: [
      { id: 'linux-file-marker-v1', name: 'Marcador Linux', version: 1, technique_id: null },
    ],
  },
}

function respond(value: unknown) {
  return { ok: true, status: 200, json: async () => value }
}
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute('open', '')
  }
  HTMLDialogElement.prototype.close = function () {
    this.removeAttribute('open')
  }
})
function mount(component: React.ReactNode, notify = vi.fn()) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <NoticeContext.Provider value={notify}>{component}</NoticeContext.Provider>
    </QueryClientProvider>,
  )
}
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  location.hash = ''
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

it('requires a different administrator for real approval in the interface', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(respond({ ...detail, requested_by: 'admin' })))
  mount(<ExecutionDetail id="run" user={administrator} />)
  await screen.findByText('Linux autorizado')
  expect(screen.queryByRole('button', { name: 'Revisar e aprovar' })).not.toBeInTheDocument()
  expect(screen.getByText(/Comprovante do executor não comprova detecção/)).toBeInTheDocument()
})

it('submits explicit real approval only after scope review', async () => {
  const fetcher = vi.fn().mockResolvedValue(respond(detail))
  vi.stubGlobal('fetch', fetcher)
  mount(<ExecutionDetail id="run" user={administrator} />)
  await userEvent.click(await screen.findByRole('button', { name: 'Revisar e aprovar' }))
  await userEvent.click(screen.getByRole('checkbox', { name: /Autorizo o efeito real/ }))
  await userEvent.click(screen.getByRole('button', { name: 'Aprovar escopo' }))
  await waitFor(() =>
    expect(
      fetcher.mock.calls.some(
        ([url, options]) =>
          String(url).endsWith('/approve') &&
          JSON.parse(options.body).confirm_real_execution === true,
      ),
    ).toBe(true),
  )
})

it('shows only Linux-compatible tests when creating a real campaign', async () => {
  location.hash = 'campaigns/new'
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      respond(
        url.includes('/labs')
          ? {
              items: [
                {
                  id: 'linux',
                  name: 'Linux Lab',
                  kind: 'linux',
                  synthetic: false,
                  authorized: true,
                  environment_version: 1,
                },
              ],
            }
          : url.includes('/tests')
            ? {
                items: [
                  {
                    id: 'marker',
                    name: 'Marcador real',
                    execution_kind: 'linux_marker',
                    approved: true,
                  },
                  { id: 'demo', name: 'Simulação Demo', execution_kind: 'demo', approved: true },
                ],
              }
            : { items: [] },
      ),
    ),
  )
  mount(<Campaigns user={administrator} />)
  await screen.findByRole('option', { name: /Linux Lab/ })
  await userEvent.selectOptions(screen.getByLabelText('Laboratório'), 'linux')
  expect(await screen.findByText('Marcador real')).toBeInTheDocument()
  expect(screen.queryByText('Simulação Demo')).not.toBeInTheDocument()
})

it('registration has no arbitrary target or command fields and displays API failures', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ error: { message: 'Runner Linux desconectado' } }),
    }),
  )
  const notify = vi.fn()
  mount(<LinuxRegistration onClose={vi.fn()} />, notify)
  expect(screen.queryByLabelText(/URL|Comando|Endereço/)).not.toBeInTheDocument()
  await userEvent.type(screen.getByLabelText('Responsável'), 'Responsável local')
  await userEvent.type(
    screen.getByLabelText('Revisão do isolamento'),
    'Rede isolada e identidade revisadas neste host de laboratório.',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Registrar binding' }))
  await waitFor(() => expect(notify).toHaveBeenCalledWith('Runner Linux desconectado', true))
  expect(screen.getByRole('heading', { name: 'Registrar Linux Lab revisado' })).toBeInTheDocument()
})

it('requests ATT&CK coverage from the API using the selected mode', async () => {
  const fetcher = vi.fn().mockResolvedValue(respond({ items: [], total: 0 }))
  vi.stubGlobal('fetch', fetcher)
  mount(<Catalog />)
  await userEvent.selectOptions(await screen.findByLabelText('Modo da cobertura ATT&CK'), 'linux')
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('mode=linux'))).toBe(true),
  )
})
