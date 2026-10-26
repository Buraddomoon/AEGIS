import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CoveragePage } from './CoveragePage'
import { localTimestamp, runOptions } from './CoverageFilters'
import { NoticeContext } from './lib'

const hash = 'a'.repeat(64)
const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
const metrics = {
  catalogued_techniques: 706,
  evaluated_techniques: 1,
  historical_evaluated_techniques: 1,
  scope_sha256: hash,
  total_runs: 1,
  completed_tests: 1,
  valid_tests: 1,
  detected_percentage: 100,
  outcomes: { DETECTED: 1 },
  denominator: 'Testes válidos',
  scope: 'Demo · recorte de teste',
  limitation: 'Dados sintéticos',
  unversioned_runs: 0,
  selection: { evaluation_catalog: { version: '20.0' } },
}
function mount(notify = vi.fn()) {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <NoticeContext.Provider value={notify}>
        <CoveragePage />
      </NoticeContext.Provider>
    </QueryClientProvider>,
  )
}
function transport() {
  return vi.fn(async (url: string) => {
    if (url.includes('/catalog/attack/releases')) return ok({ items: [], total: 0 })
    if (url.includes('/coverage/runs')) return ok({ items: [], total: 0, scope_sha256: hash })
    if (url.includes('/coverage/report'))
      return {
        ok: false,
        status: 409,
        json: async () => ({ error: { message: 'Referência do recorte mudou.' } }),
      }
    if (url.includes('catalog_release=legacy'))
      return ok({
        ...metrics,
        catalogued_techniques: null,
        evaluated_techniques: null,
        selection: { evaluation_catalog: null },
        unversioned_runs: 1,
        valid_tests: 0,
        detected_percentage: null,
      })
    return ok(metrics)
  })
}
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('explicit coverage selection', () => {
  it('keeps the last applied scope visible and blocks export until filters are applied', async () => {
    const fetch = transport()
    vi.stubGlobal('fetch', fetch)
    mount()
    const exportButton = await screen.findByRole('button', { name: 'Exportar recorte JSON' })
    await waitFor(() => expect(exportButton).toBeEnabled())
    await userEvent.selectOptions(screen.getByLabelText('Modo dos indicadores'), 'linux')
    expect(exportButton).toBeDisabled()
    expect(screen.getByText(/Filtros alterados/)).toBeInTheDocument()
    expect(fetch.mock.calls.some(([url]) => url.includes('/coverage?mode=linux'))).toBe(false)
    await userEvent.click(screen.getByRole('button', { name: 'Aplicar recorte' }))
    await waitFor(() =>
      expect(fetch.mock.calls.some(([url]) => url.includes('/coverage?mode=linux'))).toBe(true),
    )
  })

  it('renders legacy denominators as unknown and never as zero percent', async () => {
    vi.stubGlobal('fetch', transport())
    mount()
    await userEvent.selectOptions(await screen.findByLabelText('Release dos indicadores'), 'legacy')
    await userEvent.click(screen.getByRole('button', { name: 'Aplicar recorte' }))
    await screen.findByText('Sem denominador válido')
    expect(screen.getByText('Versão não registrada no legado')).toBeInTheDocument()
    expect(screen.queryByText('0% neste recorte')).not.toBeInTheDocument()
  })

  it('binds an export to the preview hash and surfaces a stale-reference error', async () => {
    const fetch = transport(),
      notify = vi.fn()
    vi.stubGlobal('fetch', fetch)
    mount(notify)
    const button = await screen.findByRole('button', { name: 'Exportar recorte JSON' })
    await waitFor(() => expect(button).toBeEnabled())
    await userEvent.click(button)
    await waitFor(() => expect(notify).toHaveBeenCalledWith('Referência do recorte mudou.', true))
    expect(
      fetch.mock.calls.some(([url]) =>
        url.includes(
          `/coverage/report?mode=demo&catalog_release=all&expected_scope_sha256=${hash}&format=json`,
        ),
      ),
    ).toBe(true)
  })

  it('converts a local timestamp to an explicit UTC instant and rejects normalized invalid dates', () => {
    expect(localTimestamp('2026-10-26T12:30:00')).toBe(new Date(2026, 9, 26, 12, 30).toISOString())
    expect(() => localTimestamp('2026-02-30T12:30:00')).toThrow()
    expect(() => localTimestamp('1720000000')).toThrow()
    expect(localTimestamp('')).toBeNull()
  })

  it('loads options from all pages without silently dropping the next page', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(ok({ items: [{ id: 'a' }], total: 2, scope_sha256: hash }))
      .mockResolvedValueOnce(ok({ items: [{ id: 'b' }], total: 2, scope_sha256: hash }))
    vi.stubGlobal('fetch', fetch)
    expect((await runOptions('mode=demo')).items.map((r) => r.id)).toEqual(['a', 'b'])
    expect(fetch.mock.calls[1][0]).toContain('offset=1')
  })

  it.each(['mixed scope', 'duplicate', 'incomplete', 'changed total'])(
    'refuses %s option pages',
    async (kind) => {
      const second = {
        items: kind === 'incomplete' ? [] : [{ id: kind === 'duplicate' ? 'a' : 'b' }],
        total: kind === 'changed total' ? 3 : 2,
        scope_sha256: kind === 'mixed scope' ? 'b'.repeat(64) : hash,
      }
      vi.stubGlobal(
        'fetch',
        vi
          .fn()
          .mockResolvedValueOnce(ok({ items: [{ id: 'a' }], total: 2, scope_sha256: hash }))
          .mockResolvedValueOnce(ok(second)),
      )
      await expect(runOptions('mode=demo')).rejects.toThrow()
    },
  )
})
