import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { MappingPreview } from './MappingPreview'
import type { ConversionProfile, RuleVersion, SigmaMappingPreview } from './types'

const saved: RuleVersion = {
  id: 'v1',
  version: 1,
  content: '',
  sha256: 'a'.repeat(64),
  created_at: '',
  techniques: [],
}
const profile: ConversionProfile = {
  id: 'wazuh-aegis-marker/1',
  name: 'Marcador',
  sha256: 'b'.repeat(64),
  status: 'candidate_not_executable',
  target: 'opensearch_lucene',
  logsource: { product: 'aegis' },
  fields: { AegisSchema: 'data.aegis.schema' },
  index_mapping_verified: false,
}
function response(version = saved): SigmaMappingPreview {
  return {
    rule_id: 'r1',
    rule_version_id: version.id,
    rule_version: version.version,
    sha256: version.sha256,
    preview_version: 'sigma-mapping-preview/1',
    profile,
    pipeline: {
      version: 'sigma-mapping-preview/1',
      profile_id: profile.id,
      profile_sha256: profile.sha256,
      pysigma_version: '2.0.1',
      sha256: 'c'.repeat(64),
    },
    document_sha256: 'd'.repeat(64),
    status: 'previewed',
    blockers: [],
    before_detection: { selection: { AegisSchema: 'aegis-json/1' }, condition: 'selection' },
    after_detection: { selection: { 'data.aegis.schema': 'aegis-json/1' }, condition: 'selection' },
    can_convert: false,
    query_generated: false,
    siem_queried: false,
    deployment_performed: false,
    index_mapping_verified: false,
    limitations: ['Sem consulta e sem validação do índice.'],
  }
}
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})
function mount(handler: (path: string) => Promise<SigmaMappingPreview> = async () => response()) {
  const fetcher = vi.fn(async (path: string) => ({ ok: true, json: async () => handler(path) }))
  vi.stubGlobal('fetch', fetcher)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function View({ version = saved }: { version?: RuleVersion }) {
    return (
      <QueryClientProvider client={client}>
        <MappingPreview ruleId="r1" saved={version} profile={profile} />
      </QueryClientProvider>
    )
  }
  const mounted = render(<View />)
  return { ...mounted, fetcher, client, View }
}
it('requests only after an explicit click and shows real before/after without a query action', async () => {
  const { fetcher } = mount()
  expect(fetcher).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: 'Gerar prévia de campos' }))
  await screen.findByRole('heading', { name: 'Prévia de campos gerada' })
  expect(screen.getByText(/"data.aegis.schema"/)).toBeInTheDocument()
  expect(screen.getByText(/Conversão SIEM continua bloqueada/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Converter' })).not.toBeInTheDocument()
  expect(fetcher.mock.calls[0][0]).toContain('/v1/mapping-preview?profile_id=')
  await userEvent.click(screen.getByRole('button', { name: 'Ocultar prévia de campos' }))
  expect(screen.queryByText(/"data.aegis.schema"/)).not.toBeInTheDocument()
})
it.each([
  'rule',
  'version',
  'hash',
  'profile',
  'pipeline',
  'pipeline_hash',
  'contract',
  'missing',
  'unsafe_flag',
] as const)('rejects mismatched %s response', async (mismatch) => {
  mount(async () => {
    const data = response()
    if (mismatch === 'rule') data.rule_id = 'other'
    if (mismatch === 'version') data.rule_version_id = 'other'
    if (mismatch === 'hash') data.sha256 = 'f'.repeat(64)
    if (mismatch === 'profile') data.profile = { ...profile, sha256: 'f'.repeat(64) }
    if (mismatch === 'pipeline')
      data.pipeline = { ...data.pipeline, profile_sha256: 'f'.repeat(64) }
    if (mismatch === 'pipeline_hash') data.pipeline = { ...data.pipeline, sha256: 'invalid' }
    if (mismatch === 'contract') data.preview_version = 'unexpected' as typeof data.preview_version
    if (mismatch === 'missing') data.after_detection = null
    if (mismatch === 'unsafe_flag') Object.assign(data, { query_generated: true })
    return data
  })
  await userEvent.click(screen.getByRole('button', { name: 'Gerar prévia de campos' }))
  await screen.findByText(/A prévia recebida não corresponde/)
  expect(screen.queryByRole('heading', { name: 'Prévia de campos gerada' })).not.toBeInTheDocument()
})
it('shows an unsupported policy as unavailable without an empty success', async () => {
  mount(async () => ({
    ...response(),
    status: 'unsupported',
    before_detection: null,
    after_detection: null,
    blockers: [{ code: 'literal_string_required', message: 'Somente strings literais.' }],
  }))
  await userEvent.click(screen.getByRole('button', { name: 'Gerar prévia de campos' }))
  await screen.findByRole('heading', { name: 'Regra fora do subconjunto da prévia' })
  expect(screen.getByText('Somente strings literais.')).toBeInTheDocument()
  expect(screen.queryByText('Depois · detection normalizada')).not.toBeInTheDocument()
})
it('does not show stale success after a failed refetch', async () => {
  let fail = false
  const { client } = mount(async () => {
    if (fail) throw new Error('Prévia indisponível')
    return response()
  })
  await userEvent.click(screen.getByRole('button', { name: 'Gerar prévia de campos' }))
  await screen.findByRole('heading', { name: 'Prévia de campos gerada' })
  fail = true
  await act(async () => {
    await client.invalidateQueries()
  })
  await screen.findByText('Prévia indisponível', {}, { timeout: 4000 })
  expect(screen.queryByText(/"data.aegis.schema"/)).not.toBeInTheDocument()
})
it('discards a delayed result for the previously selected version', async () => {
  let release!: (value: SigmaMappingPreview) => void
  const pending = new Promise<SigmaMappingPreview>((resolve) => {
    release = resolve
  })
  const other = { ...saved, id: 'v2', version: 2, sha256: 'e'.repeat(64) }
  const { rerender, View } = mount(async (path) =>
    path.includes('/v1/') ? pending : response(other),
  )
  await userEvent.click(screen.getByRole('button', { name: 'Gerar prévia de campos' }))
  rerender(<View version={other} />)
  await screen.findByRole('heading', { name: 'Prévia de campos gerada' })
  await act(async () => {
    release({ ...response(), status: 'unsupported', before_detection: null, after_detection: null })
  })
  expect(
    screen.queryByRole('heading', { name: 'Regra fora do subconjunto da prévia' }),
  ).not.toBeInTheDocument()
})
