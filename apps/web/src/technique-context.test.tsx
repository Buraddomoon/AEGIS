import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Catalog } from './Catalog'
import { TechniqueContext } from './TechniqueContext'
import type { TechniqueCatalogContext, ObservedTelemetry } from './TechniqueContext'
import type { ReactNode } from 'react'

const releaseId = 'a'.repeat(64)
const node = (id: string) => ({
  id,
  name: `Reference ${id}`,
  reference: `https://attack.mitre.org/${id}`,
  revoked: false,
  deprecated: false,
})
const edge = { stix_id: 'relationship--recorded', revoked: false, deprecated: false }
const context = (): TechniqueCatalogContext => ({
  status: 'available',
  catalog: {
    release_id: releaseId,
    version: '20.0',
    provenance: 'official_commit',
    source_sha256: 'c'.repeat(64),
    source_commit: 'b'.repeat(40),
  },
  document_format: 'aegis-enterprise-catalog/2',
  parent: { technique: node('T1059'), relationship: edge },
  children: [],
  telemetry: [
    {
      relationship: edge,
      strategy: node('DET0001'),
      analytic: node('AN0001'),
      component: node('DC0001'),
      data_source: { ...node('DS0001'), deprecated: true },
      log_source: { name: 'Recommended:Process', channel: 'Channel 1' },
    },
  ],
})
const observation: ObservedTelemetry = {
  execution_id: 'execution-1',
  run_id: 'run-1',
  synthetic: true,
  catalog_release_id: 'f'.repeat(64),
  catalog_version: '19.2',
  outcome: 'DETECTED',
  collection_complete: true,
  sources: [{ source: 'saved-demo-source', kind: 'alert', synthetic: true, event_count: 1 }],
}
const technique = (id: string) => ({
  ...node(id),
  tactics: ['execution'],
  platforms: ['Linux'],
  parent_id: id.includes('.') ? 'T1059' : null,
  dataset_version: '20.0',
  coverage: 'NOT_TESTED',
  catalog_status: 'active',
  coverage_applicable: true,
  description: 'Recorded description',
  mode: 'demo',
  tests: [],
  planned_rule_links: [],
  coverage_history: [],
  limitation: 'No deployed rules',
})
const ok = (value: unknown) => ({ ok: true, status: 200, json: async () => value })
function mount(child: ReactNode) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 } } })}
    >
      {child}
    </QueryClientProvider>,
  )
}
function catalogFetch(detail: (url: string) => unknown) {
  return vi.fn(async (url: string) => {
    if (url === '/api/v1/catalog/attack')
      return ok({ status: 'uninitialized', current: null, counts: null })
    if (url.startsWith('/api/v1/techniques?'))
      return ok({
        items: [technique('T1059'), technique('T1059.001')],
        total: 2,
        catalog: context().catalog,
        catalog_release_id: releaseId,
      })
    return detail(url)
  })
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
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

it('navigates by exact parent ID and keeps official references separate from stored events', async () => {
  const navigate = vi.fn()
  mount(
    <TechniqueContext
      context={context()}
      observations={[observation]}
      mode="demo"
      onNavigate={navigate}
    />,
  )
  await userEvent.click(screen.getByRole('button', { name: 'T1059 · Reference T1059' }))
  expect(navigate).toHaveBeenCalledWith('T1059')
  const official = screen.getByRole('region', { name: 'Relações oficiais ATT&CK' })
  const observed = screen.getByRole('region', { name: 'Telemetria registrada nas execuções' })
  await userEvent.click(within(official).getByText(/Consultar 1 caminhos/))
  expect(within(official).getByRole('link', { name: /DC0001/ })).toHaveAttribute(
    'rel',
    'noreferrer',
  )
  expect(within(official).getByText(/Descontinuada/)).toBeInTheDocument()
  expect(within(official).queryByText(/saved-demo-source/)).not.toBeInTheDocument()
  expect(within(observed).getByText(/saved-demo-source/)).toBeInTheDocument()
  expect(within(observed).getByText(/Enterprise v19.2/)).toHaveTextContent('f'.repeat(64))
  expect(within(observed).getByRole('link', { name: 'Evidências da execução' })).toHaveAttribute(
    'href',
    '#executions/run-1',
  )
  expect(within(observed).queryByText(/Recommended:Process/)).not.toBeInTheDocument()
})

it.each([
  ['legacy_unavailable', /snapshot legado/],
  ['not_provided', /não fornece relações/],
  ['technique_absent', /fora da release atual/],
] as const)('shows %s without invented telemetry', (status, message) => {
  mount(
    <TechniqueContext
      context={{ ...context(), status, telemetry: [] }}
      observations={[]}
      mode="linux"
      onNavigate={vi.fn()}
    />,
  )
  expect(screen.getByText(message)).toBeInTheDocument()
  expect(screen.getByText('Nenhuma avaliação concluída neste modo.')).toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /DC0001/ })).not.toBeInTheDocument()
  expect(screen.getByText(/Telemetria registrada nas execuções · Linux real/)).toBeInTheDocument()
})

it('distinguishes unavailable summaries from a completed evaluation with zero recorded events', () => {
  const view = mount(<TechniqueContext mode="linux" onNavigate={vi.fn()} />)
  expect(screen.getByText(/Resumo de telemetria indisponível/)).toBeInTheDocument()
  view.rerender(
    <TechniqueContext
      context={context()}
      mode="linux"
      onNavigate={vi.fn()}
      observations={[
        {
          ...observation,
          synthetic: false,
          sources: [],
          collection_complete: false,
          catalog_release_id: null,
          catalog_version: null,
          outcome: 'INCONCLUSIVE',
        },
      ]}
    />,
  )
  expect(screen.getByText('Nenhum evento registrado nesta avaliação.')).toBeInTheDocument()
  expect(
    screen.getByText('Versão do catálogo não registrada', { exact: false }),
  ).toBeInTheDocument()
  expect(screen.getByText(/Coleta incompleta/)).toHaveTextContent('INCONCLUSIVE')
  expect(screen.getByText(/Zero eventos/)).toBeInTheDocument()
})

it('navigates child and parent while preserving mode, release and matrix filters', async () => {
  const fetch = catalogFetch((url) => {
    const id = url.includes('T1059.001?') ? 'T1059.001' : 'T1059'
    const c = context()
    if (id === 'T1059') {
      c.parent = null
      c.children = [{ technique: node('T1059.001'), relationship: edge }]
      c.telemetry = []
      c.status = 'not_provided'
    }
    return ok({ ...technique(id), catalog_context: c, observed_telemetry: [] })
  })
  vi.stubGlobal('fetch', fetch)
  mount(<Catalog />)
  await userEvent.type(await screen.findByLabelText('Pesquisar técnica'), 'T1059.001')
  await userEvent.click(await screen.findByRole('button', { name: /Reference T1059\.001/ }))
  await userEvent.click(await screen.findByRole('button', { name: 'T1059 · Reference T1059' }))
  await userEvent.click(
    await screen.findByRole('button', { name: 'T1059.001 · Reference T1059.001' }),
  )
  expect(await screen.findByRole('button', { name: 'T1059 · Reference T1059' })).toBeInTheDocument()
  expect(screen.getByLabelText('Pesquisar técnica')).toHaveValue('T1059.001')
  expect(
    fetch.mock.calls
      .filter(([url]) => url.includes('/techniques/T'))
      .every(([url]) => url.endsWith(`?mode=demo&catalog_release_id=${releaseId}`)),
  ).toBe(true)
})

it.each(['release', 'mode', 'identity'])('refuses a mismatched %s response', async (mismatch) => {
  vi.stubGlobal(
    'fetch',
    catalogFetch(() =>
      ok({
        ...technique(mismatch === 'identity' ? 'T1057' : 'T1059'),
        mode: mismatch === 'mode' ? 'linux' : 'demo',
        catalog_context: {
          ...context(),
          catalog: {
            ...context().catalog,
            release_id: mismatch === 'release' ? 'f'.repeat(64) : releaseId,
          },
        },
      }),
    ),
  )
  mount(<Catalog />)
  await userEvent.click(await screen.findByText('Reference T1059'))
  expect(await screen.findByText(/Contexto da técnica mudou/)).toBeInTheDocument()
  expect(screen.queryByText('Recorded description')).not.toBeInTheDocument()
})

it('clears the previous detail when navigating to an API error', async () => {
  vi.stubGlobal(
    'fetch',
    catalogFetch((url) =>
      url.includes('T1059.001?')
        ? ok({ ...technique('T1059.001'), catalog_context: context(), observed_telemetry: [] })
        : {
            ok: false,
            status: 409,
            json: async () => ({ error: { message: 'Catálogo mudou durante a navegação' } }),
          },
    ),
  )
  mount(<Catalog />)
  await userEvent.click(await screen.findByRole('button', { name: /Reference T1059\.001/ }))
  await userEvent.click(await screen.findByRole('button', { name: 'T1059 · Reference T1059' }))
  expect(await screen.findByText('Catálogo mudou durante a navegação')).toBeInTheDocument()
  expect(screen.queryByText('Recorded description')).not.toBeInTheDocument()
  expect(screen.queryByText(/Consultar 1 caminhos/)).not.toBeInTheDocument()
})

it('does not restore a closed Demo detail when its delayed response arrives after switching mode', async () => {
  let resolve!: (value: unknown) => void
  vi.stubGlobal(
    'fetch',
    catalogFetch(
      () =>
        new Promise((done) => {
          resolve = done
        }),
    ),
  )
  mount(<Catalog />)
  await userEvent.click(await screen.findByRole('button', { name: /Reference T1059\.001/ }))
  await userEvent.selectOptions(screen.getByLabelText('Modo da cobertura ATT&CK'), 'linux')
  await screen.findByLabelText('Modo da cobertura ATT&CK')
  resolve(
    ok({
      ...technique('T1059.001'),
      catalog_context: context(),
      observed_telemetry: [observation],
    }),
  )
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.queryByText(/saved-demo-source/)).not.toBeInTheDocument()
})
