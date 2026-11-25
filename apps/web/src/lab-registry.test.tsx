import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { LinuxRegistration } from './LinuxRegistration'
import { LabAssets } from './LabAssets'
import { Laboratories } from './Management'
import { Campaigns } from './Operations'
import { NoticeContext } from './lib'

const entry = {
  id: 'closed-one',
  revision: 2,
  owner: 'Reviewed owner',
  isolation: 'Host-owned isolation review for this fixture.',
  laboratory_id: 'lab-one',
  asset_id: 'asset-one',
  platform: 'Linux',
  test_id: 'linux-file-marker/v1',
  review_hash: 'a'.repeat(64),
}
const asset = {
  id: 'asset-one',
  laboratory_id: 'lab-one',
  name: 'Linux endpoint',
  platform: 'Linux',
  external_id: 'explicit-native-id',
  synthetic: false,
  authorized: false,
  connection_status: 'disconnected',
  available_test_ids: ['marker'],
}
const respond = (data: unknown) => ({ ok: true, status: 200, json: async () => data })
function mount(component: React.ReactNode) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 } } })}
    >
      <NoticeContext.Provider value={vi.fn()}>{component}</NoticeContext.Provider>
    </QueryClientProvider>,
  )
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
  location.hash = ''
})

it('submits the exact reviewed connection hash and host-owned owner', async () => {
  const fetcher = vi.fn(async (url: string, _options?: RequestInit) =>
    respond(url.includes('/connections') ? { mode: 'registry', items: [entry] } : {}),
  )
  vi.stubGlobal('fetch', fetcher)
  mount(<LinuxRegistration onClose={vi.fn()} />)
  await userEvent.selectOptions(await screen.findByLabelText('Conexão aprovada'), entry.id)
  expect(screen.getByLabelText('Responsável')).toHaveValue(entry.owner)
  expect(screen.getByLabelText('Responsável')).toHaveAttribute('readonly')
  await userEvent.type(
    screen.getByLabelText('Revisão do isolamento'),
    'Current operator review, no execution or network effect.',
  )
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(screen.getByRole('button', { name: 'Registrar binding' }))
  await waitFor(() =>
    expect(
      fetcher.mock.calls.some(([url, ...rest]) => {
        if (!url.endsWith('/register')) return false
        const body = JSON.parse((rest[0] as RequestInit).body as string)
        return (
          body.registry_id === entry.id &&
          body.confirm_registry_hash === entry.review_hash &&
          body.owner === entry.owner &&
          !body.url &&
          !body.command
        )
      }),
    ).toBe(true),
  )
})

it('clears confirmation when the reviewed connection changes', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      respond({
        mode: 'registry',
        items: [entry, { ...entry, id: 'closed-two', laboratory_id: 'lab-two' }],
      }),
    ),
  )
  mount(<LinuxRegistration onClose={vi.fn()} />)
  await userEvent.selectOptions(await screen.findByLabelText('Conexão aprovada'), entry.id)
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.selectOptions(screen.getByLabelText('Conexão aprovada'), 'closed-two')
  expect(screen.getByRole('checkbox')).not.toBeChecked()
})

it('blocks registration when registry loading fails', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok: false,
      status: 409,
      json: async () => ({ error: { message: 'Registro indisponível' } }),
    })),
  )
  mount(<LinuxRegistration onClose={vi.fn()} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Registro indisponível')
  expect(screen.getByRole('button', { name: 'Registrar binding' })).toBeDisabled()
})

it('shows revoked/disconnected/no-capacity states and requests history for the exact asset', async () => {
  const fetcher = vi.fn(async (url: string) =>
    respond(
      url.includes('/history')
        ? { items: [], total: 0 }
        : {
            items: [
              asset,
              {
                ...asset,
                id: 'windows',
                name: 'Windows unavailable',
                platform: 'Windows',
                available_test_ids: [],
              },
              { ...asset, id: 'foreign', laboratory_id: 'other', name: 'Foreign' },
            ],
          },
    ),
  )
  vi.stubGlobal('fetch', fetcher)
  mount(<LabAssets laboratoryId="lab-one" />)
  await screen.findByText('Linux endpoint')
  expect(screen.getAllByText(/Revogado/)).toHaveLength(2)
  expect(screen.getByText('Sem capacidade de execução revisada')).toBeInTheDocument()
  expect(screen.queryByText('Foreign')).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Histórico do ativo Linux endpoint' }))
  await screen.findByText('Nenhuma execução registrada')
  expect(
    fetcher.mock.calls.some(([url]) => url.includes('/assets/asset-one/history?offset=0&limit=25')),
  ).toBe(true)
})

it('resets asset and tests when changing laboratories and filters each allowlist', async () => {
  location.hash = 'campaigns/new'
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      respond(
        url.includes('/labs')
          ? {
              items: [
                { id: 'lab-one', name: 'First lab', authorized: true, kind: 'linux' },
                { id: 'lab-two', name: 'Second lab', authorized: true, kind: 'linux' },
              ],
            }
          : url.includes('/assets')
            ? {
                items: [
                  { ...asset, authorized: true },
                  {
                    ...asset,
                    id: 'asset-two',
                    laboratory_id: 'lab-two',
                    name: 'Second asset',
                    authorized: true,
                    available_test_ids: [],
                  },
                ],
              }
            : url.includes('/tests')
              ? {
                  items: [
                    {
                      id: 'marker',
                      name: 'Exact Linux marker',
                      approved: true,
                      execution_kind: 'linux_marker',
                    },
                    {
                      id: 'unreviewed',
                      name: 'Unavailable test',
                      approved: true,
                      execution_kind: 'linux_marker',
                    },
                  ],
                }
              : { items: [] },
      ),
    ),
  )
  mount(
    <Campaigns user={{ id: 'admin', username: 'admin', role: 'administrator', active: true }} />,
  )
  await screen.findByRole('option', { name: /First lab/ })
  await userEvent.selectOptions(await screen.findByLabelText('Laboratório'), 'lab-one')
  await userEvent.selectOptions(await screen.findByLabelText('Ativo autorizado'), asset.id)
  await userEvent.click(await screen.findByRole('checkbox', { name: /Exact Linux marker/ }))
  expect(screen.queryByText('Unavailable test')).not.toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Laboratório'), 'lab-two')
  expect(screen.getByLabelText('Ativo autorizado')).toHaveValue('')
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
})

it('never presents Linux trust or authorization controls for a Windows laboratory', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      respond(
        url.endsWith('/labs')
          ? {
              items: [
                {
                  id: 'windows-lab',
                  name: 'Windows offline',
                  kind: 'windows',
                  synthetic: false,
                  authorized: false,
                  execution_capability: 'disabled',
                  connection_status: 'disconnected',
                },
              ],
            }
          : { items: [] },
      ),
    ),
  )
  mount(
    <Laboratories user={{ id: 'admin', username: 'admin', role: 'administrator', active: true }} />,
  )
  await screen.findByText('Windows offline')
  expect(screen.queryByLabelText('Confiança Linux')).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: /Autorizar Linux Lab|Verificar mTLS/ }),
  ).not.toBeInTheDocument()
})
