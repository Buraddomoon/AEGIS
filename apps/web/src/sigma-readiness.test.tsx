import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { RuleReadiness } from './RuleReadiness'
import type {
  BackendCompatibility,
  ConversionProfile,
  ConversionReadiness,
  Rule,
  RuleVersion,
} from './types'

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
  content: '',
  sha256: String(v).repeat(64),
  created_at: '',
  techniques: [],
}))
const profile: ConversionProfile = {
  id: 'wazuh-aegis-marker/1',
  name: 'Marcador ÆGIS',
  sha256: 'a'.repeat(64),
  status: 'candidate_not_executable',
  target: 'opensearch_lucene',
  logsource: { product: 'aegis' },
  fields: { AegisSchema: 'data.aegis.schema' },
  index_mapping_verified: false,
}
const backend: BackendCompatibility = {
  status: 'blocked',
  snapshot_reviewed_at: '2026-10-22',
  snapshot_sha256: 'b'.repeat(64),
  packages: [],
  blockers: [],
}
function diagnostic(v: number): ConversionReadiness {
  return {
    rule_id: rule.id,
    rule_version_id: `version-${v}`,
    rule_version: v,
    sha256: String(v).repeat(64),
    readiness_version: 'sigma-readiness/1',
    pysigma_version: '2.0.1',
    profile,
    backend,
    status: 'blocked',
    can_convert: false,
    conversion_performed: false,
    deployment_performed: false,
    logsource_matches: v === 1,
    field_mapping_complete: v === 1,
    mappings: [{ source_field: 'AegisSchema', target_field: v === 1 ? 'data.aegis.schema' : null }],
    keyword_selections: [],
    field_references: [],
    blockers: [
      {
        code: 'dependency_unsatisfied',
        message: 'Backend exige pySigma anterior à versão instalada.',
      },
    ],
    limitations: ['Mapeamento candidato não demonstra compatibilidade.'],
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
    path.endsWith('/versions')
      ? { items: versions }
      : path.endsWith('/conversion-profiles')
        ? { items: [profile], backend }
        : diagnostic(path.includes('version-1') ? 1 : 2),
) {
  const fetcher = vi.fn(async (path: string, _options?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () => handler(path),
  }))
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <RuleReadiness rule={rule} onClose={vi.fn()} />
    </QueryClientProvider>,
  )
  return fetcher
}
it('shows blockers and missing fields; historical mapping does not enable conversion', async () => {
  const fetcher = mount()
  await screen.findByText('Sem mapeamento')
  expect(screen.getByText('Backend exige pySigma anterior à versão instalada.')).toBeInTheDocument()
  expect(screen.getByText('Conversão bloqueada')).toBeInTheDocument()
  await userEvent.selectOptions(screen.getByLabelText('Versão para preparação'), 'version-1')
  await screen.findByText('data.aegis.schema')
  expect(screen.getByText(/Campos declarados mapeados: Sim/)).toBeInTheDocument()
  expect(screen.getByText('Conversão bloqueada')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Converter' })).not.toBeInTheDocument()
  expect(fetcher.mock.calls.every(([, options]) => (options?.method ?? 'GET') === 'GET')).toBe(true)
})
it.each(['hash', 'version', 'profile'])('rejects mismatched %s context', async (mismatch) => {
  mount(async (path) => {
    if (path.endsWith('/versions')) return { items: versions }
    if (path.endsWith('/conversion-profiles')) return { items: [profile], backend }
    const result = diagnostic(2)
    if (mismatch === 'hash') result.sha256 = 'f'.repeat(64)
    if (mismatch === 'version') result.rule_version_id = 'other'
    if (mismatch === 'profile') result.profile = { ...profile, sha256: 'f'.repeat(64) }
    return result
  })
  await screen.findByText(
    'O diagnóstico recebido não corresponde à versão e ao perfil selecionados.',
  )
  expect(screen.queryByText('Conversão bloqueada')).not.toBeInTheDocument()
})
it('does not show a delayed response for another selected version', async () => {
  let release!: (value: unknown) => void
  const pending = new Promise((resolve) => {
    release = resolve
  })
  mount(async (path) =>
    path.endsWith('/versions')
      ? { items: versions }
      : path.endsWith('/conversion-profiles')
        ? { items: [profile], backend }
        : path.includes('version-2')
          ? pending
          : diagnostic(1),
  )
  await screen.findByLabelText('Versão para preparação')
  await userEvent.selectOptions(screen.getByLabelText('Versão para preparação'), 'version-1')
  await screen.findByText('data.aegis.schema')
  release(diagnostic(2))
  expect(screen.queryByText('Sem mapeamento')).not.toBeInTheDocument()
})
it('reports unavailable metadata instead of suggesting compatibility', async () => {
  mount(async (path) => {
    if (path.endsWith('/versions')) return { items: versions }
    throw new Error('Metadados indisponíveis')
  })
  await screen.findByText('Metadados indisponíveis', {}, { timeout: 4000 })
  expect(screen.queryByText(/Campos declarados mapeados/)).not.toBeInTheDocument()
})
it('handles an empty profile catalog explicitly', async () => {
  mount(async (path) => (path.endsWith('/versions') ? { items: versions } : { items: [], backend }))
  await screen.findByText('Preparação indisponível')
  expect(screen.queryByText('Conversão bloqueada')).not.toBeInTheDocument()
})
it('makes unresolved field references visible even when declared names have paths', async () => {
  mount(async (path) => {
    if (path.endsWith('/versions')) return { items: [versions[1]] }
    if (path.endsWith('/conversion-profiles')) return { items: [profile], backend }
    return { ...diagnostic(1), field_mapping_complete: false, field_references: ['UnknownField'] }
  })
  await screen.findByText('Referências fieldref sem tratamento: UnknownField')
  expect(screen.getByText(/Campos declarados mapeados: Não/)).toBeInTheDocument()
})
