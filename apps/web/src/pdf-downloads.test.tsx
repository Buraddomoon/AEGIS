import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, expect, it, vi } from 'vitest'
import { Reports } from './Operations'
import { NoticeContext } from './lib'

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data })

function mount(mode: 'success' | 'failure' | 'wrong-type' = 'success') {
  const notify = vi.fn()
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  const create = vi.fn(() => 'blob:pdf-fixture')
  vi.stubGlobal(
    'URL',
    class extends URL {
      static createObjectURL = create
      static revokeObjectURL = vi.fn()
    },
  )
  const fetcher = vi.fn(async (path: string) => {
    if (path.includes('format=pdf')) {
      if (mode === 'failure')
        return {
          ok: false,
          status: 413,
          json: async () => ({ error: { message: 'Reduza o recorte ou exporte JSON/HTML.' } }),
        }
      return {
        ok: true,
        status: 200,
        headers: new Headers({
          'content-type': mode === 'wrong-type' ? 'application/json' : 'application/pdf',
        }),
        blob: async () => new Blob(['%PDF-fixture'], { type: 'application/pdf' }),
      }
    }
    if (path.includes('/catalog/')) return ok({ items: [], total: 0 })
    if (path.includes('/campaigns?'))
      return ok({ items: [{ id: 'campaign', name: 'Validação Demo' }] })
    return ok({
      items: [
        {
          id: 'run-42',
          campaign_id: 'campaign',
          synthetic: true,
          ended_at: '2026-11-05T12:00:00Z',
        },
      ],
      total: 1,
      offset: 0,
      limit: 100,
    })
  })
  vi.stubGlobal('fetch', fetcher)
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <NoticeContext.Provider value={notify}>
        <Reports />
      </NoticeContext.Provider>
    </QueryClientProvider>,
  )
  return { notify, click, create, fetcher }
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

it('downloads the selected persistent report as PDF using its run id', async () => {
  const { notify, click, create, fetcher } = mount()
  await userEvent.click(await screen.findByRole('button', { name: 'PDF' }))
  await waitFor(() => expect(notify).toHaveBeenCalledWith('PDF exportado.'))
  expect(fetcher).toHaveBeenCalledWith('/api/v1/reports/run-42?format=pdf', {
    credentials: 'same-origin',
  })
  expect(create).toHaveBeenCalledWith(expect.any(Blob))
  expect(click).toHaveBeenCalledTimes(1)
  expect(click.mock.instances[0]).toHaveProperty('download', 'aegis-run-42.pdf')
})

it.each(['failure', 'wrong-type'] as const)(
  'surfaces %s without downloading or claiming success',
  async (mode) => {
    const { notify, click, create } = mount(mode)
    await userEvent.click(await screen.findByRole('button', { name: 'PDF' }))
    await waitFor(() => expect(notify).toHaveBeenCalledWith(expect.any(String), true))
    expect(click).not.toHaveBeenCalled()
    expect(create).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalledWith('PDF exportado.')
  },
)

it('blocks cached PDF exports while the report filters have unapplied changes', async () => {
  mount()
  const button = await screen.findByRole('button', { name: 'PDF' })
  await waitFor(() => expect(button).toBeEnabled())
  await userEvent.selectOptions(screen.getByLabelText('Modo dos relatórios'), 'linux')
  expect(button).toBeDisabled()
})
