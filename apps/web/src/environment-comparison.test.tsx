import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { EnvironmentComparison, type EnvironmentReport } from './EnvironmentComparison'
import { downloadFile } from './lib'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

it('does not save a download canceled while its body was arriving', async () => {
  let finish!: (blob: Blob) => void
  const controller = new AbortController(),
    click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok: true,
      blob: () =>
        new Promise<Blob>((resolve) => {
          finish = resolve
        }),
    })),
  )
  const saving = downloadFile('/coverage/environments/report', 'report.json', controller.signal)
  await waitFor(() => expect(finish).toBeDefined())
  controller.abort()
  finish(new Blob(['old snapshot']))
  await expect(saving).rejects.toThrow()
  expect(click).not.toHaveBeenCalled()
})

function report(params: URLSearchParams): EnvironmentReport {
  const side = (prefix: string) => ({
    laboratory_id: params.get(prefix + '_laboratory_id')!,
    synthetic: params.get(prefix + '_mode') === 'demo',
    total_runs: 1,
    valid_tests: 1,
    detected_tests: 1,
    excluded_tests: 0,
    detected_percentage: 100,
    denominator: 'DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY',
    selection: Object.fromEntries(
      ['laboratory_id', 'mode', 'catalog_release', 'requested_from', 'requested_before'].map(
        (k) => [k, params.get(prefix + '_' + k)],
      ),
    ),
    cohorts: [],
    members: [],
  })
  return {
    kind: 'environment-comparison',
    report_version: 'aegis-environment-comparison/1',
    integrity_sha256: 'a'.repeat(64),
    snapshot_at: '2026-11-23T12:00:00Z',
    before: side('before'),
    after: side('after'),
    comparison: {
      classification: 'descriptive',
      reasons: ['different_recorded_contexts', 'after:unknown_catalog_context'],
      context_differences: [],
      detected_rate_delta_percentage_points: null,
      limitation: 'Sem melhoria causal ou proteção geral.',
    },
  }
}
function setup(load?: (p: URLSearchParams) => Promise<EnvironmentReport>, failExport = false) {
  const fetch = vi.fn(
    async (
      path: string,
    ): Promise<{
      ok: boolean
      status: number
      json: () => Promise<unknown>
      headers?: Headers
      blob?: () => Promise<Blob>
    }> => {
      if (path.includes('/environments/report'))
        return {
          ok: !failExport,
          status: failExport ? 409 : 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ error: { message: 'Snapshot mudou' } }),
          blob: async () => new Blob(['snapshot']),
        }
      return {
        ok: true,
        status: 200,
        json: async () =>
          path.includes('/labs')
            ? {
                items: [
                  { id: 'lab-a', name: 'Lab A', kind: 'demo' },
                  { id: 'lab-b', name: 'Lab B', kind: 'demo' },
                  { id: 'lab-c', name: 'Lab C', kind: 'linux' },
                ],
              }
            : path.includes('/releases')
              ? { items: [], total: 0 }
              : load
                ? load(new URLSearchParams(path.split('?')[1]))
                : report(new URLSearchParams(path.split('?')[1])),
      }
    },
  )
  vi.stubGlobal('fetch', fetch)
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <EnvironmentComparison />
    </QueryClientProvider>,
  )
  return fetch
}
async function choose() {
  await userEvent.click(screen.getByRole('button', { name: 'Escolher dois laboratórios' }))
  await screen.findAllByRole('option', { name: 'Lab A · Demo sintético' })
  await userEvent.selectOptions(screen.getByLabelText('Laboratório A'), 'lab-a')
  await userEvent.selectOptions(screen.getByLabelText('Laboratório B'), 'lab-b')
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Consultar laboratórios' })).toBeEnabled(),
  )
}

it('loads laboratories only on explicit opening and refuses the same lab', async () => {
  const fetch = setup()
  expect(fetch).not.toHaveBeenCalled()
  await choose()
  await userEvent.selectOptions(screen.getByLabelText('Laboratório B'), 'lab-a')
  expect(screen.getByRole('button', { name: 'Consultar laboratórios' })).toBeDisabled()
})

it('shows descriptive reasons, denominators and no delta; filters invalidate all exports', async () => {
  setup()
  await choose()
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await screen.findByText('Comparação descritiva · sem delta')
  expect(screen.getByText('B: Release ATT&CK desconhecida')).toBeInTheDocument()
  expect(screen.getByText(/Delta em pontos percentuais: não calculado/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Exportar laboratórios JSON' })).toBeEnabled()
  await userEvent.selectOptions(screen.getByLabelText('Release B'), 'legacy')
  expect(screen.queryByText('Comparação descritiva · sem delta')).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Exportar laboratórios JSON' }),
  ).not.toBeInTheDocument()
})

it('discards a delayed response after selection changes', async () => {
  let finish!: (r: EnvironmentReport) => void, requested!: URLSearchParams
  setup((params) => {
    requested = params
    return new Promise((r) => {
      finish = r
    })
  })
  await choose()
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await userEvent.selectOptions(screen.getByLabelText('Laboratório B'), 'lab-c')
  await act(async () => finish(report(requested)))
  expect(
    screen.queryByRole('button', { name: 'Exportar laboratórios JSON' }),
  ).not.toBeInTheDocument()
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Consultar laboratórios' })).toBeEnabled(),
  )
})

it('refuses a response belonging to other cuts', async () => {
  setup(async (p) => {
    const r = report(p)
    r.after.selection.catalog_release = 'legacy'
    return r
  })
  await choose()
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await screen.findByText(/Resposta incompatível/)
  expect(
    screen.queryByRole('button', { name: 'Exportar laboratórios JSON' }),
  ).not.toBeInTheDocument()
})

it('sends the complete snapshot hash/date and discards success on export drift', async () => {
  const fetch = setup(undefined, true)
  await choose()
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await screen.findByText('Comparação descritiva · sem delta')
  await userEvent.click(screen.getByRole('button', { name: 'Exportar laboratórios JSON' }))
  await screen.findByText('Snapshot mudou')
  const path = fetch.mock.calls.find(([p]) => p.includes('/environments/report'))![0]
  const p = new URLSearchParams(path.split('?')[1])
  expect(p.get('snapshot_at')).toBe('2026-11-23T12:00:00Z')
  expect(p.get('expected_snapshot_sha256')).toBe('a'.repeat(64))
  expect(p.get('before_laboratory_id')).toBe('lab-a')
  expect(p.get('after_laboratory_id')).toBe('lab-b')
  expect(
    screen.queryByRole('button', { name: 'Exportar laboratórios JSON' }),
  ).not.toBeInTheDocument()
})

it('keeps mixed modes separate and explains incomparability', async () => {
  const fetch = setup(async (p) => {
    const r = report(p)
    r.comparison.classification = 'incomparable'
    r.comparison.reasons = ['different_modes']
    return r
  })
  await choose()
  await userEvent.selectOptions(screen.getByLabelText('Laboratório B'), 'lab-c')
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await screen.findByText('Recortes incomparáveis · sem delta')
  expect(screen.getByText(/Demo e real têm origens distintas/)).toBeInTheDocument()
  expect(fetch.mock.calls.some(([p]) => p.includes('after_mode=linux'))).toBe(true)
})

it('can export all three formats from the same snapshot', async () => {
  const fetch = setup()
  // The downloader enforces the PDF media type, so provide a dedicated response.
  const original = fetch.getMockImplementation()!
  fetch.mockImplementation(async (path: string) =>
    path.includes('/environments/report')
      ? {
          ok: true,
          status: 200,
          headers: new Headers({
            'content-type': path.includes('format=pdf') ? 'application/pdf' : 'application/json',
          }),
          json: async () => ({}),
          blob: async () => new Blob(['snapshot']),
        }
      : original(path),
  )
  vi.stubGlobal(
    'URL',
    class extends URL {
      static createObjectURL = vi.fn(() => 'blob:fixture')
      static revokeObjectURL = vi.fn()
    },
  )
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  await choose()
  await userEvent.click(screen.getByRole('button', { name: 'Consultar laboratórios' }))
  await screen.findByText('Comparação descritiva · sem delta')
  for (const format of ['PDF', 'HTML', 'JSON']) {
    await userEvent.click(screen.getByRole('button', { name: `Exportar laboratórios ${format}` }))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: `Exportar laboratórios ${format}` })).toBeEnabled(),
    )
  }
  const paths = fetch.mock.calls
    .filter(([p]) => p.includes('/environments/report'))
    .map(([p]) => new URLSearchParams(p.split('?')[1]))
  expect(paths).toHaveLength(3)
  expect(new Set(paths.map((p) => p.get('expected_snapshot_sha256'))).size).toBe(1)
  expect(new Set(paths.map((p) => p.get('snapshot_at'))).size).toBe(1)
})
