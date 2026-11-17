import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AtomicCatalog } from './AtomicCatalog'
import type { User } from './types'

const admin: User = { id: 'admin', username: 'admin', role: 'administrator', active: true }
const entry = {
  id: 'entry',
  guid: 'official-guid',
  name: 'Official fixture metadata',
  technique_id: 'T1059.004',
  platforms: ['linux'],
  attack_mapping_status: 'active',
  review_status: 'pending',
  review_sequence: 0,
  executable: false,
  approved: false,
  available_for_new_scope: false,
  source: {
    document_id: 'doc',
    source_commit: 'a'.repeat(40),
    source_sha256: 'b'.repeat(64),
    source_path: 'atomics/T1059.004/T1059.004.yaml',
    provenance: 'operator_supplied',
    imported_at: '2026-11-17T10:00:00Z',
    imported_by: 'admin',
  },
}
const detail = {
  ...entry,
  description: '<script>untrusted-text</script>',
  dependencies: [{ description: 'Declared dependency', has_prereq: true, has_setup: false }],
  dependency_executor: 'bash',
  input_arguments: { file: { type: 'path', description: 'A declared file', has_default: true } },
  executor: 'sh',
  has_cleanup: false,
  elevation_required: true,
  latest_review: null,
}
const page = (items = [entry], total = items.length) => ({ items, total, offset: 0, limit: 20 })
const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data })
const failure = () => ({
  ok: false,
  status: 409,
  json: async () => ({ error: { message: 'Revisão alterada; recarregue.' } }),
})
function mount(user = admin) {
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false, retryDelay: 0 } } })
  render(
    <QueryClientProvider client={cache}>
      <AtomicCatalog user={user} />
    </QueryClientProvider>,
  )
  return cache
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
})

it('filters through the API and paginates every imported version', async () => {
  const fetch = vi.fn(async (_url: string) => ok(page([entry], 21)))
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText(entry.name)
  await userEvent.type(screen.getByLabelText('Pesquisar Atomic'), 'T1059.004')
  await userEvent.type(screen.getByLabelText('Plataforma Atomic'), 'linux')
  await userEvent.selectOptions(screen.getByLabelText('Revisão Atomic'), 'reviewed')
  await userEvent.click(screen.getByText('Filtrar Atomic'))
  await waitFor(() =>
    expect(
      fetch.mock.calls.some((call) =>
        String(call[0]).includes('q=T1059.004&platform=linux&review_status=reviewed'),
      ),
    ).toBe(true),
  )
  await userEvent.click(screen.getByText('Próxima página Atomic'))
  await waitFor(() =>
    expect(fetch.mock.calls.some((call) => String(call[0]).includes('offset=20'))).toBe(true),
  )
  expect(screen.getByText('Metadado revisado', { exact: false })).toBeTruthy()
  expect(screen.getByText(/Pendente de revisão · Não executável/)).toBeInTheDocument()
})

it.each(['viewer', 'operator'] as const)(
  'allows %s to inspect with no import/review action',
  async (role) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        ok(url.includes('/reviews') ? page([]) : url.includes('/entries/') ? detail : page()),
      ),
    )
    mount({ ...admin, role })
    await screen.findByText(entry.name)
    expect(screen.queryByText('Importar metadados Atomic')).not.toBeInTheDocument()
    await userEvent.click(screen.getByText('Inspecionar ' + entry.name))
    const dialog = await screen.findByRole('dialog')
    await within(dialog).findByText(entry.guid)
    expect(within(dialog).getByText('<script>untrusted-text</script>')).toBeInTheDocument()
    expect(dialog.querySelector('script')).toBeNull()
    expect(within(dialog).getByText('Ausente; limpeza não garantida')).toBeInTheDocument()
    expect(within(dialog).getByText(/Default omitido/)).toBeInTheDocument()
    expect(within(dialog).getByText(entry.source.source_commit)).toBeInTheDocument()
    expect(within(dialog).queryByText('Registrar revisão de metadado')).not.toBeInTheDocument()
  },
)

it('imports explicit YAML, commit and hash without execution requests', async () => {
  const fetch = vi.fn(async (_url: string, options?: RequestInit) =>
    options?.method === 'POST' ? ok({ unchanged: false }) : ok(page([])),
  )
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText('Nenhum metadado Atomic encontrado')
  await userEvent.click(screen.getByText('Importar metadados Atomic'))
  fireEvent.change(screen.getByLabelText('Commit oficial informado'), {
    target: { value: 'a'.repeat(40) },
  })
  fireEvent.change(screen.getByLabelText('SHA256 do YAML'), { target: { value: 'b'.repeat(64) } })
  fireEvent.change(screen.getByLabelText('YAML Atomic'), {
    target: { value: 'attack_technique: T1059.004' },
  })
  await userEvent.click(screen.getByText('Importar somente metadados'))
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  const posts = fetch.mock.calls.filter((call) => call[1]?.method === 'POST')
  expect(posts).toHaveLength(1)
  expect(posts[0][0]).toBe('/api/v1/catalog/atomic/imports')
  expect(JSON.parse(String(posts[0][1]!.body))).toEqual({
    source_commit: 'a'.repeat(40),
    source_sha256: 'b'.repeat(64),
    content: 'attack_technique: T1059.004',
  })
})

it('rejects the UTF-8 byte limit before posting', async () => {
  const fetch = vi.fn(async (_url: string) => ok(page([])))
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText('Nenhum metadado Atomic encontrado')
  await userEvent.click(screen.getByText('Importar metadados Atomic'))
  fireEvent.change(screen.getByLabelText('Commit oficial informado'), {
    target: { value: 'a'.repeat(40) },
  })
  fireEvent.change(screen.getByLabelText('SHA256 do YAML'), { target: { value: 'b'.repeat(64) } })
  fireEvent.change(screen.getByLabelText('YAML Atomic'), { target: { value: 'é'.repeat(40000) } })
  await userEvent.click(screen.getByText('Importar somente metadados'))
  expect(await screen.findByRole('alert')).toHaveTextContent('YAML excede 64 KiB UTF-8.')
  expect(fetch.mock.calls.every((call) => !String(call[0]).includes('/imports'))).toBe(true)
})

it('posts review sequence and shows stale review errors without implying execution approval', async () => {
  const fetch = vi.fn(async (url: string, options?: RequestInit) =>
    options?.method === 'POST'
      ? failure()
      : ok(url.includes('/reviews') ? page([]) : url.includes('/entries/') ? detail : page()),
  )
  vi.stubGlobal('fetch', fetch)
  mount()
  await screen.findByText(entry.name)
  await userEvent.click(screen.getByText('Inspecionar ' + entry.name))
  await screen.findByText(entry.guid)
  await userEvent.type(screen.getByLabelText('Justificativa da revisão'), 'Metadata only review')
  await userEvent.click(screen.getByText('Registrar revisão de metadado'))
  expect(await screen.findByRole('alert')).toHaveTextContent('Revisão alterada')
  const post = fetch.mock.calls.find((call) => call[1]?.method === 'POST')!
  expect(JSON.parse(String(post[1]!.body))).toEqual({
    decision: 'reviewed',
    note: 'Metadata only review',
    expected_sequence: 0,
  })
  expect(screen.getAllByText(/execução desabilitada/).length).toBeGreaterThan(0)
})

it('hides cached entries when refresh fails', async () => {
  let fails = false
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => (fails ? failure() : ok(page()))),
  )
  const cache = mount()
  await screen.findByText(entry.name)
  cache.setQueryDefaults(['/catalog/atomic?limit=20&offset=0'], { retry: false })
  fails = true
  await userEvent.click(screen.getByText('Atualizar catálogo Atomic'))
  expect(await screen.findByRole('alert')).toHaveTextContent('Revisão alterada')
  expect(screen.queryByText('Inspecionar ' + entry.name)).not.toBeInTheDocument()
})
