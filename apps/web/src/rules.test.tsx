import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { NoticeContext } from './lib'
import { RuleTestLinks } from './RuleTestLinks'
import { ScopeChanges } from './ScopeChanges'
import type { Rule, RuleTestLink, Test, User } from './types'

const rule: Rule = {
  id: 'rule',
  title: 'Regra atual',
  sigma_id: 'uuid',
  latest_version: 2,
  created_at: '',
  status: '',
}
const user: User = { id: 'admin', username: 'reviewer', role: 'administrator', active: true }
const test: Test = {
  id: 'demo-shell',
  name: 'Shell benigno',
  version: 1,
  execution_kind: 'demo',
  description: '',
  technique_id: 'T1059.004',
  behavior: 'shell',
  cleanup: '',
  prerequisites: '',
  demo_outcome: 'DETECTED',
  approved: true,
  platform: 'Synthetic',
  risk: 'synthetic',
}
const link: RuleTestLink = {
  id: 'review-one',
  rule_id: rule.id,
  current_rule_title: rule.title,
  rule_version_id: 'version-one',
  rule_version: 1,
  rule_sha256: 'a'.repeat(64),
  latest_rule_version: 2,
  test_id: test.id,
  test_name: test.name,
  test_version: 1,
  current_test_version: 1,
  rationale: 'Revisão anterior preservada.',
  created_by: 'operator',
  created_at: '2026-10-22T12:00:00Z',
  retired_at: null,
  retired_by: null,
  review_required: true,
  purpose: 'planning_only_not_deployed',
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
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
})

let cache: QueryClient
function mount(role: User['role'] = 'administrator', failed = false, items = [link]) {
  const fetcher = vi.fn(async (path: string, options?: RequestInit) => {
    if (failed)
      return {
        ok: false,
        status: 503,
        json: async () => ({ error: { message: 'Consulta indisponível' } }),
      }
    const value = options?.method
      ? { id: 'new-review' }
      : path.includes('/versions')
        ? { items: [{ id: 'version-two', version: 2, sha256: 'b'.repeat(64) }] }
        : path.includes('/tests')
          ? { items: [test] }
          : { items, total: items.length }
    return { ok: true, status: 200, json: async () => value }
  })
  vi.stubGlobal('fetch', fetcher)
  cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={cache}>
      <NoticeContext.Provider value={vi.fn()}>
        <RuleTestLinks rule={rule} user={{ ...user, role }} onClose={vi.fn()} />
      </NoticeContext.Provider>
    </QueryClientProvider>,
  )
  return fetcher
}

it('reviews exact versions and explicitly replaces the prior link', async () => {
  const fetcher = mount()
  await screen.findByText('Revisão necessária')
  expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
  await userEvent.selectOptions(screen.getByLabelText('Teste associado'), 'demo-shell')
  await userEvent.type(
    screen.getByLabelText('Justificativa da associação'),
    'Correlacionar a fonte de criação de processos e o comportamento benigno de shell.',
  )
  await userEvent.click(screen.getByLabelText(/Revisei as versões/))
  await userEvent.click(screen.getByRole('button', { name: 'Registrar revisão' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(true),
  )
  const [, options] = fetcher.mock.calls.find(([, value]) => value?.method === 'POST')!
  expect(JSON.parse(String(options!.body))).toMatchObject({
    rule_version_id: 'version-two',
    confirm_rule_sha256: 'b'.repeat(64),
    confirm_test_version: 1,
    replaces_id: 'review-one',
  })
  expect(screen.getAllByText(/não comprova detecção/).length).toBeGreaterThan(0)
})

it('retires only after confirmation and preserves history controls', async () => {
  const fetcher = mount('operator')
  await userEvent.click(await screen.findByRole('button', { name: 'Retirar vínculo' }))
  expect(fetcher.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(false)
  await userEvent.click(screen.getByRole('button', { name: 'Confirmar retirada' }))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([, options]) => options?.method === 'DELETE')).toBe(true),
  )
  await userEvent.click(screen.getByLabelText('Incluir histórico de revisões'))
  await waitFor(() =>
    expect(fetcher.mock.calls.some(([path]) => path.includes('include_retired=true'))).toBe(true),
  )
})

it('viewers inspect reviews without mutation controls', async () => {
  mount('viewer')
  await screen.findByText('Revisão necessária')
  expect(screen.queryByRole('button', { name: 'Retirar vínculo' })).not.toBeInTheDocument()
  expect(screen.queryByLabelText('Teste associado')).not.toBeInTheDocument()
})

it.each(['version', 'link'])(
  'invalidates confirmation when %s changes in query data',
  async (kind) => {
    mount()
    await screen.findByText('Revisão necessária')
    await userEvent.selectOptions(screen.getByLabelText('Teste associado'), 'demo-shell')
    await userEvent.type(
      screen.getByLabelText('Justificativa da associação'),
      'Revisão humana do comportamento e da fonte de eventos associados.',
    )
    const checkbox = screen.getByLabelText(/Revisei as versões/)
    await userEvent.click(checkbox)
    expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeEnabled()
    act(() => {
      if (kind === 'version')
        cache.setQueryData(['/rules/rule/versions'], {
          items: [{ id: 'version-three', version: 3, sha256: 'c'.repeat(64) }],
        })
      else
        cache.setQueryData(['/rule-test-links?rule_id=rule&test_id=demo-shell'], {
          items: [{ ...link, id: 'another-review' }],
          total: 1,
        })
    })
    await waitFor(() => expect(checkbox).not.toBeChecked())
    expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
  },
)

it('renders empty state and connector errors without showing successful reviews', async () => {
  mount('administrator', false, [])
  await screen.findByText('Nenhum vínculo registrado')
  cleanup()
  mount('administrator', true)
  await screen.findByText('Consulta indisponível', {}, { timeout: 4000 })
  expect(screen.getByRole('button', { name: 'Registrar revisão' })).toBeDisabled()
})

it('distinguishes unknown legacy context from a recorded absence of links', () => {
  render(
    <ScopeChanges
      changes={{
        rule_versions: [{ key: 'rule', before: 1, after: 2 }],
        test_definitions: [],
        environment: [],
        rule_test_links: null,
        link_context_recorded: false,
      }}
    />,
  )
  expect(screen.getByText(/Esse contexto é desconhecido/)).toBeInTheDocument()
  expect(screen.getByText('Versões do inventário Sigma · 1 alteração(ões)')).toBeInTheDocument()
  expect(
    screen.queryByText('Associações entre regras e testes · sem alterações registradas'),
  ).not.toBeInTheDocument()
})
