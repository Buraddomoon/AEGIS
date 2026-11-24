import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { Recommendations, matchingAnalysis } from './Recommendations'
import type { RunDetail } from './types'

function fixture(): RunDetail {
  return {
    id: 'run',
    synthetic: true,
    campaign_id: 'campaign',
    campaign_name: 'Demo',
    objective: 'Inspecionar fatos.',
    requested_by: 'fixture',
    laboratory_id: 'lab',
    schedule_id: null,
    scope_hash: 'f'.repeat(64),
    state: 'COMPLETED',
    error: null,
    cancel_requested: false,
    created_at: '2026-11-23T00:00:00Z',
    started_at: null,
    ended_at: null,
    approval: null,
    schedule_occurrence: null,
    steps: [],
    scope: {
      environment_version: 1,
      asset_id: 'asset',
      mode: 'demo',
      synthetic: true,
      rule_versions: {},
      clock_skew_seconds: 5,
      ingestion_window_seconds: 120,
      test_definitions: [],
    },
    executions: [
      {
        id: 'execution',
        test_id: 'demo-test',
        state: 'COMPLETED',
        marker: 'fixture',
        executed: true,
        synthetic: true,
        result: null,
        evidence: [],
        runner_receipt: null,
        runner_cleanup: null,
        events: [
          {
            id: 'event',
            source_id: 'fixture',
            kind: 'telemetry',
            timestamp: '2026-11-23T00:00:00Z',
            rule_id: null,
            synthetic: true,
            raw: {},
            sha256: 'e'.repeat(64),
            source: 'demo',
          },
        ],
      },
    ],
    recommendation_analysis: {
      kind: 'new_analysis',
      run_id: 'run',
      synthetic: true,
      policy: { version: 'aegis-recommendations/1' },
      policy_sha256: 'a'.repeat(64),
      input_sha256: 'b'.repeat(64),
      integrity_sha256: 'c'.repeat(64),
      limitations: ['Ausência de alerta não comprova vulnerabilidade.'],
      items: [
        {
          execution_id: 'execution',
          execution_index: 0,
          test_id: 'demo-test',
          code: 'observed_not_alerted',
          priority: 60,
          reason: 'Observação registrada sem alerta.',
          action: 'Revisar a regra esperada no escopo aprovado.',
          facts: { outcome: 'OBSERVED_NOT_ALERTED' },
          evidence: [
            { event_id: 'event', source: 'demo', sha256: 'e'.repeat(64), event_present: true },
          ],
        },
      ],
    },
  }
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

it('shows technical advice, facts, linked evidence and origin without executing anything', async () => {
  const run = fixture(),
    inspect = vi.fn(),
    fetcher = vi.fn()
  vi.stubGlobal('fetch', fetcher)
  render(<Recommendations run={run} onEvent={inspect} onRefresh={vi.fn()} />)
  expect(screen.getByText(/Análise nova separada/)).toBeInTheDocument()
  expect(screen.getByText(/Dados sintéticos/)).toBeInTheDocument()
  expect(screen.getByText('Observação registrada sem alerta.')).toBeInTheDocument()
  expect(screen.getByText('Revisar a regra esperada no escopo aprovado.')).toBeInTheDocument()
  expect(screen.getByText(/OBSERVED_NOT_ALERTED/)).toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Inspecionar evidência event' }))
  expect(inspect).toHaveBeenCalledWith(run.executions[0].events[0])
  expect(fetcher).not.toHaveBeenCalled()
})

it.each(['run', 'origin', 'policy', 'hash', 'item', 'evidence'])(
  'blocks incompatible %s without offering exports',
  (kind) => {
    const run = fixture(),
      analysis = run.recommendation_analysis!
    if (kind === 'run') analysis.run_id = 'other'
    if (kind === 'origin') analysis.synthetic = false
    if (kind === 'policy') analysis.policy.version = 'future'
    if (kind === 'hash') analysis.integrity_sha256 = 'invalid'
    if (kind === 'item') analysis.items[0].execution_id = 'other'
    if (kind === 'evidence') analysis.items[0].evidence = [null as never]
    expect(matchingAnalysis(analysis, run)).toBeFalsy()
    render(<Recommendations run={run} onEvent={vi.fn()} onRefresh={vi.fn()} />)
    expect(screen.getByText(/Análise indisponível ou incompatível/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Exportar/ })).not.toBeInTheDocument()
  },
)

it('does not invent an event or its hash for an orphan link', () => {
  const run = fixture()
  run.recommendation_analysis!.items[0].evidence[0] = {
    event_id: 'missing',
    event_present: false,
    source: null,
    sha256: null,
  }
  render(<Recommendations run={run} onEvent={vi.fn()} onRefresh={vi.fn()} />)
  expect(screen.getByText('Evento vinculado indisponível: missing')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Inspecionar evidência/ })).not.toBeInTheDocument()
})

it('exports the exact preview hash and blocks stale exports after conflict until refresh', async () => {
  const run = fixture(),
    refresh = vi.fn().mockResolvedValue(undefined)
  const fetcher = vi.fn().mockResolvedValue({
    ok: false,
    json: async () => ({ error: { message: 'Análise mudou; reconsulte.' } }),
  })
  vi.stubGlobal('fetch', fetcher)
  render(<Recommendations run={run} onEvent={vi.fn()} onRefresh={refresh} />)
  await userEvent.click(screen.getByRole('button', { name: 'Exportar recomendações JSON' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Análise mudou')
  const url = new URL(fetcher.mock.calls[0][0], 'http://localhost')
  expect(url.pathname).toBe('/api/v1/reports/run/recommendations')
  expect(url.searchParams.get('expected_analysis_sha256')).toBe(
    run.recommendation_analysis!.integrity_sha256,
  )
  expect(url.searchParams.get('format')).toBe('json')
  expect(screen.getByRole('button', { name: 'Exportar recomendações HTML' })).toBeDisabled()
  await userEvent.click(screen.getByRole('button', { name: 'Reconsultar execução' }))
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Exportar recomendações HTML' })).toBeEnabled(),
  )
  expect(refresh).toHaveBeenCalledTimes(1)
})

it('aborts a download when the snapshot changes and ignores its late response', async () => {
  const run = fixture()
  let resolve!: (value: unknown) => void
  const fetcher = vi.fn().mockReturnValue(
    new Promise((done) => {
      resolve = done
    }),
  )
  vi.stubGlobal('fetch', fetcher)
  const { rerender } = render(<Recommendations run={run} onEvent={vi.fn()} onRefresh={vi.fn()} />)
  await userEvent.click(screen.getByRole('button', { name: 'Exportar recomendações JSON' }))
  const next = structuredClone(run)
  next.recommendation_analysis!.integrity_sha256 = 'd'.repeat(64)
  rerender(<Recommendations run={next} onEvent={vi.fn()} onRefresh={vi.fn()} />)
  expect(fetcher.mock.calls[0][1].signal.aborted).toBe(true)
  resolve({ ok: false, json: async () => ({ error: { message: 'Erro antigo' } }) })
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Exportar recomendações JSON' })).toBeEnabled(),
  )
  expect(screen.queryByText('Erro antigo')).not.toBeInTheDocument()
})
