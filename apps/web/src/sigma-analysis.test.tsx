import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { RuleAnalysis } from './RuleAnalysis'
import type { Rule, RuleVersion, SigmaAnalysis } from './types'

const rule: Rule = {
  id: 'rule',
  title: 'Nome atual',
  sigma_id: 'uuid',
  latest_version: 2,
  created_at: '',
  status: '',
}
const versions: RuleVersion[] = [2, 1].map((v) => ({
  id: `version-${v}`,
  version: v,
  content: 'saved',
  sha256: String(v).repeat(64),
  created_at: '',
  techniques: [],
}))
function analysis(v: number): SigmaAnalysis {
  return {
    rule_id: rule.id,
    rule_version_id: `version-${v}`,
    rule_version: v,
    sha256: String(v).repeat(64),
    analyzer_version: 'sigma-static/1',
    pysigma_version: '2.0.1',
    status: v === 1 ? 'no_findings_in_selected_checks' : 'findings',
    checks: ['condition_resolution', 'unused_selection'],
    skipped_checks: [],
    findings:
      v === 1
        ? []
        : [
            {
              code: 'unused_selection',
              message: 'Seleção não usada.',
              severity: 'HIGH',
              origin: 'aegis_static',
              selection: 'unused',
            },
          ],
    facts: {
      logsource: { product: 'linux' },
      declared_fields: ['CommandLine'],
      conditions: ['selection'],
      selections: ['selection', 'unused'],
      keyword_selections: [],
    },
    compatibility: {
      status: 'not_configured',
      backend: null,
      pipeline: null,
      conversion_performed: false,
      deployment_performed: false,
    },
    limitations: ['Ausência de achados não comprova eficácia.'],
  }
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
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})
function mount(
  handler: (path: string) => Promise<unknown> = async (path) =>
    path.endsWith('/versions') ? { items: versions } : analysis(path.includes('version-1') ? 1 : 2),
) {
  const fetcher = vi.fn(async (path: string) => ({
    ok: true,
    status: 200,
    json: async () => handler(path),
  }))
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <RuleAnalysis rule={rule} onClose={vi.fn()} />
    </QueryClientProvider>,
  )
  return fetcher
}
it('shows findings, exact hash and partial-analysis limits; supports history', async () => {
  const fetcher = mount()
  await screen.findByText('Seleção não usada.')
  expect(screen.getByText('Alta')).toBeInTheDocument()
  expect(screen.getByText(/Campos declarados: CommandLine/)).toBeInTheDocument()
  expect(screen.getByText(/Nenhuma conversão ou implantação realizada/)).toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Versão para análise'), 'version-1')
  await screen.findByText('Nenhum achado nos checks executados')
  expect(screen.queryByText('Seleção não usada.')).not.toBeInTheDocument()
  expect(screen.getByText(/SHA-256:/)).toHaveTextContent('1'.repeat(64))
  expect(fetcher.mock.calls.some(([path]) => path.endsWith('/version-1/analysis'))).toBe(true)
})
it('does not display a late response under another version', async () => {
  let release!: (value: unknown) => void
  const pending = new Promise((resolve) => {
    release = resolve
  })
  mount(async (path) =>
    path.endsWith('/versions')
      ? { items: versions }
      : path.includes('version-2')
        ? pending
        : analysis(1),
  )
  await screen.findByLabelText('Versão para análise')
  await userEvent.selectOptions(screen.getByLabelText('Versão para análise'), 'version-1')
  await screen.findByText('Nenhum achado nos checks executados')
  release(analysis(2))
  await waitFor(() => expect(screen.queryByText('Seleção não usada.')).not.toBeInTheDocument())
  expect(screen.getByLabelText('Versão para análise')).toHaveValue('version-1')
})
it('rejects inconsistent version identity or content hash', async () => {
  mount(async (path) =>
    path.endsWith('/versions') ? { items: versions } : { ...analysis(2), sha256: '0'.repeat(64) },
  )
  await screen.findByText('A análise recebida não corresponde à versão selecionada.')
  expect(screen.queryByText('Seleção não usada.')).not.toBeInTheDocument()
})
it('handles missing versions without pretending an analysis was performed', async () => {
  mount(async () => ({ items: [] }))
  await screen.findByText('Nenhuma versão disponível para análise.')
  expect(screen.queryByText('Nenhum achado nos checks executados')).not.toBeInTheDocument()
})
it('displays API failure rather than an empty successful result', async () => {
  mount(async (path) => {
    if (path.endsWith('/versions')) return { items: versions }
    throw new Error('Limite de análise indisponível')
  })
  await screen.findByText('Limite de análise indisponível', {}, { timeout: 4000 })
  expect(screen.queryByText('Nenhum achado nos checks executados')).not.toBeInTheDocument()
})
