import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AttackCatalogStatus, loadTechniques } from './AttackCatalog'
import { Catalog } from './Catalog'
import type { ReactNode } from 'react'

const release = {
  id: 'a'.repeat(64),
  dataset_version: '20.0',
  provenance: 'official_commit',
  source_commit: 'b'.repeat(40),
  source_sha256: 'c'.repeat(64),
  license_sha256: 'd'.repeat(64),
  source_url: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/pinned.json',
  created_at: '2026-10-23T12:00:00Z',
}
const status = {
  status: 'ready',
  current: release,
  counts: { active: 3, revoked: 1, deprecated: 1, absent: 0 },
}
const technique = {
  id: 'T1066',
  name: 'Indicator Removal from Tools',
  tactics: ['defense-evasion'],
  platforms: ['Linux'],
  parent_id: null,
  dataset_version: '20.0',
  coverage: 'NOT_TESTED',
  catalog_status: 'revoked',
  coverage_applicable: false,
  revoked: true,
  deprecated: false,
}
const page = (items: unknown[], total = items.length, id = release.id) => ({
  items,
  total,
  catalog: { release_id: id, version: '20.0' },
  catalog_release_id: id,
})
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
function mount(children: ReactNode) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      {children}
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
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal')
  Reflect.deleteProperty(HTMLDialogElement.prototype, 'close')
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('versioned ATT&CK catalog', () => {
  it('binds subsequent pages to one release and keeps all techniques', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(ok(page([{ ...technique, id: 'T1059' }], 2)))
      .mockResolvedValueOnce(ok(page([technique], 2)))
    vi.stubGlobal('fetch', fetch)
    expect((await loadTechniques('demo', 'all')).items).toHaveLength(2)
    expect(fetch.mock.calls[1][0]).toContain(
      `offset=1&mode=demo&lifecycle=all&catalog_release_id=${release.id}`,
    )
  })

  it.each(['mixed', 'duplicate', 'incomplete', 'missing metadata'])(
    'refuses %s matrix pages',
    async (scenario) => {
      const second =
        scenario === 'mixed'
          ? page([technique], 2, 'f'.repeat(64))
          : scenario === 'duplicate'
            ? page([{ ...technique, id: 'T1059' }], 2)
            : scenario === 'incomplete'
              ? page([], 2)
              : { items: [technique], total: 2 }
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockResolvedValueOnce(ok(page([{ ...technique, id: 'T1059' }], 2)))
          .mockResolvedValueOnce(ok(second)),
      )
      await expect(loadTechniques('demo', 'all')).rejects.toThrow()
    },
  )

  it('opens an immutable historical snapshot and searches through its API', async () => {
    const fetch = vi.fn(async (url: string) => {
      if (url === '/api/v1/catalog/attack') return ok(status)
      if (url.includes(`/releases/${release.id}/techniques`))
        return ok({ items: [technique], total: 1 })
      if (url.includes('/releases?')) return ok({ items: [release], total: 1 })
      throw new Error(`Unexpected endpoint: ${url}`)
    })
    vi.stubGlobal('fetch', fetch)
    mount(<AttackCatalogStatus expectedRelease={release.id} onRefresh={vi.fn()} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Histórico do catálogo' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Inspecionar snapshot' }))
    expect(await screen.findByText(technique.name)).toBeInTheDocument()
    expect(screen.getByText('Revogada')).toBeInTheDocument()
    expect(screen.getByText(/não comprova execução ou detecção/)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Pesquisar no snapshot histórico'), 'T1066')
    expect(fetch.mock.calls.some(([url]) => url.includes('q=T1066&limit=50&offset=0'))).toBe(true)
  })

  it('requires refresh when the status no longer matches the matrix release', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok(status)))
    const refresh = vi.fn()
    mount(<AttackCatalogStatus expectedRelease={'f'.repeat(64)} onRefresh={refresh} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Recarregar consulta' }))
    expect(refresh).toHaveBeenCalledOnce()
    expect(screen.queryByRole('button', { name: 'Histórico do catálogo' })).not.toBeInTheDocument()
  })

  it('filters lifecycle through the API and never labels retirement as detection coverage', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url === '/api/v1/catalog/attack') return ok(status)
        if (url.includes('lifecycle=revoked')) return ok(page([technique]))
        return ok(page([]))
      }),
    )
    mount(<Catalog />)
    await userEvent.selectOptions(
      await screen.findByLabelText('Filtrar por estado no catálogo'),
      'revoked',
    )
    await screen.findByText(technique.name)
    await userEvent.click(screen.getByRole('button', { name: 'Visualização em tabela' }))
    expect(screen.getByText('Não aplicável à release atual')).toBeInTheDocument()
    expect(screen.getByLabelText('Filtrar por cobertura')).toBeDisabled()
  })
})
