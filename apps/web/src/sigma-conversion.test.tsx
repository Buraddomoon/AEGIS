import { createHash, webcrypto } from 'node:crypto'
import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { ConversionResult, type QueryArtifact, type QueryContract } from './RuleConversion'
import type { RuleVersion } from './types'

const saved: RuleVersion = {
  id: 'v1',
  version: 1,
  content: '',
  sha256: 'a'.repeat(64),
  created_at: '',
  techniques: [],
}
function hash(value: unknown): string {
  function ordered(v: unknown): unknown {
    if (Array.isArray(v)) return v.map(ordered)
    if (v && typeof v === 'object')
      return Object.fromEntries(
        Object.entries(v)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([k, x]) => [k, ordered(x)]),
      )
    return v
  }
  return createHash('sha256')
    .update(JSON.stringify(ordered(value)))
    .digest('hex')
}
const definition = {
  version: 'sigma-query/1',
  profile: {
    id: 'aegis-marker-lucene/1',
    name: 'Marcador',
    sha256: 'b'.repeat(64),
    index_mapping_verified: false as const,
  },
  packages: {
    pysigma: '1.5.1',
    'pysigma-backend-opensearch': '2.0.3',
    'pysigma-backend-elasticsearch': '2.1.1',
  },
  pipeline: 'FieldMappingTransformation/1',
  output_format: 'default',
  lock_sha256: 'c'.repeat(64),
  implementation_sha256: 'd'.repeat(64),
}
const contract: QueryContract = { ...definition, sha256: hash(definition) }
function response(version = saved): QueryArtifact {
  const query = 'data.aegis.schema:one'
  const body = {
    rule_id: 'r1',
    rule_version_id: version.id,
    rule_version: version.version,
    sha256: version.sha256,
    conversion_version: 'sigma-query/1',
    contract,
    status: 'converted' as const,
    blockers: [],
    query,
    query_sha256: createHash('sha256').update(query).digest('hex'),
    conversion_performed: true,
    siem_queried: false as const,
    deployment_performed: false as const,
    index_mapping_verified: false as const,
    limitations: ['Consulta offline, não implantada e sem comprovação de eficácia.'],
  }
  return { ...body, document_sha256: hash(body) }
}
function seal(data: QueryArtifact) {
  const { document_sha256: _, ...body } = data
  return { ...body, document_sha256: hash(body) }
}
beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})
function mount(handler: (path: string) => Promise<QueryArtifact> = async () => response()) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (path: string) => ({ ok: true, json: async () => handler(path) })),
  )
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function View({
    version = saved,
    profile = contract,
  }: {
    version?: RuleVersion
    profile?: QueryContract
  }) {
    return (
      <QueryClientProvider client={client}>
        <ConversionResult ruleId="r1" saved={version} contract={profile} />
      </QueryClientProvider>
    )
  }
  return { ...render(<View />), client, View }
}
it('shows a verified query with provenance and allows download only after validation', async () => {
  mount()
  expect(
    screen.queryByRole('button', { name: 'Baixar consulta e procedência' }),
  ).not.toBeInTheDocument()
  await screen.findByRole('heading', { name: 'Consulta gerada para revisão' })
  expect(screen.getByText('data.aegis.schema:one')).toBeInTheDocument()
  expect(screen.getByText(/não implantada e sem comprovação/)).toBeInTheDocument()
  const create = vi.fn(() => 'blob:test')
  vi.stubGlobal('URL', { createObjectURL: create, revokeObjectURL: vi.fn() })
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  await userEvent.click(screen.getByRole('button', { name: 'Baixar consulta e procedência' }))
  expect(create).toHaveBeenCalledOnce()
  expect(click).toHaveBeenCalledOnce()
})

it.each([
  'rule',
  'version',
  'number',
  'hash',
  'profile',
  'contract',
  'document',
  'query',
  'flag',
  'missing',
  'pipeline',
])('rejects mismatched or tampered %s without a download', async (problem) => {
  mount(async () => {
    const data = structuredClone(response())
    if (problem === 'rule') data.rule_id = 'other'
    if (problem === 'version') data.rule_version_id = 'other'
    if (problem === 'number') data.rule_version = 2
    if (problem === 'hash') data.sha256 = 'f'.repeat(64)
    if (problem === 'profile') data.contract.profile.sha256 = 'f'.repeat(64)
    if (problem === 'contract') data.contract.sha256 = 'f'.repeat(64)
    if (problem === 'document') data.document_sha256 = 'f'.repeat(64)
    if (problem === 'query') data.query += ' OR injected'
    if (problem === 'flag') Object.assign(data, { deployment_performed: true })
    if (problem === 'missing') data.query = null
    if (problem === 'pipeline') data.contract.pipeline = 'unknown'
    return data
  })
  await screen.findByText(/A consulta recebida não corresponde/)
  expect(
    screen.queryByRole('heading', { name: 'Consulta gerada para revisão' }),
  ).not.toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Baixar consulta e procedência' }),
  ).not.toBeInTheDocument()
})
it('rejects a query whose document was rehashed but whose query hash is wrong', async () => {
  mount(async () => seal({ ...response(), query: 'changed' }))
  await screen.findByText(/A consulta recebida não corresponde/)
})
it('shows unsupported with its reason and without a download or empty success', async () => {
  mount(async () =>
    seal({
      ...response(),
      status: 'unsupported',
      blockers: [{ code: 'fieldref_unsupported', message: 'fieldref não suportado.' }],
      query: null,
      query_sha256: null,
      conversion_performed: false,
    }),
  )
  await screen.findByRole('heading', { name: 'Conversão não suportada para esta versão' })
  expect(screen.getByText('fieldref não suportado.')).toBeInTheDocument()
  expect(
    screen.queryByRole('button', { name: 'Baixar consulta e procedência' }),
  ).not.toBeInTheDocument()
})
it('hides cached success and download on failed refetch', async () => {
  let fail = false
  const { client } = mount(async () => {
    if (fail) throw new Error('Conversor indisponível')
    return response()
  })
  await screen.findByRole('heading', { name: 'Consulta gerada para revisão' })
  fail = true
  await act(async () => {
    await client.invalidateQueries()
  })
  await screen.findByText('Conversor indisponível')
  expect(
    screen.queryByRole('button', { name: 'Baixar consulta e procedência' }),
  ).not.toBeInTheDocument()
})
it('never displays an old delayed version response under the current selection', async () => {
  let release!: (value: QueryArtifact) => void
  const pending = new Promise<QueryArtifact>((resolve) => {
    release = resolve
  })
  const other = { ...saved, id: 'v2', version: 2, sha256: 'e'.repeat(64) }
  const { rerender, View } = mount(async (path) =>
    path.includes('/versions/v1/') ? pending : response(other),
  )
  rerender(<View version={other} />)
  await screen.findByRole('heading', { name: 'Consulta gerada para revisão' })
  await act(async () => {
    release(response())
  })
  expect(screen.getByText(/r1 · v2 · v2/)).toBeInTheDocument()
  expect(screen.queryByText(/r1 · v1 · v1/)).not.toBeInTheDocument()
})
it('does not reuse a cached query after the profile contract changes', async () => {
  const { rerender, View } = mount()
  await screen.findByRole('heading', { name: 'Consulta gerada para revisão' })
  rerender(<View profile={{ ...contract, sha256: 'f'.repeat(64) }} />)
  await screen.findByText(/A consulta recebida não corresponde/)
  expect(
    screen.queryByRole('button', { name: 'Baixar consulta e procedência' }),
  ).not.toBeInTheDocument()
})
