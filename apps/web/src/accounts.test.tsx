import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AccountSettings, UserMaintenance } from './AccountSettings'
import { Settings } from './Management'
import { NoticeContext } from './lib'
import type { User } from './types'

const admin: User = {
  id: 'admin-id',
  username: 'admin-fixture',
  role: 'administrator',
  active: true,
}
const viewer: User = { id: 'viewer-id', username: 'viewer-fixture', role: 'viewer', active: true }
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
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})
function setup(component: React.ReactNode, fail = false) {
  const notify = vi.fn(),
    close = vi.fn()
  const fetch = vi.fn(async (path: string, options?: RequestInit) => ({
    ok: !options?.method || !fail,
    status: options?.method ? (fail ? 409 : 204) : 200,
    json: async () =>
      options?.method
        ? { error: { message: 'Conflito de conta' } }
        : path.includes('/sessions')
          ? { total: 1, items: [{ expires_at: '2026-12-01T00:00:00Z', current: false }] }
          : { items: [viewer], total: 1 },
  }))
  vi.stubGlobal('fetch', fetch)
  const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={cache}>
      <NoticeContext.Provider value={notify}>{component}</NoticeContext.Provider>
    </QueryClientProvider>,
  )
  return { fetch, notify, close, cache }
}
it.each(['operator', 'viewer'] as const)(
  'keeps administration hidden for %s, own password available',
  async (role) => {
    const { fetch } = setup(<Settings user={{ ...viewer, role }} />)
    expect(screen.getByText('Trocar minha senha')).toBeInTheDocument()
    expect(screen.queryByText('Adicionar usuário')).not.toBeInTheDocument()
    expect(screen.queryByText(/Administrar viewer/)).not.toBeInTheDocument()
    await screen.findByText('1 sessões vigentes')
    expect(fetch.mock.calls.some(([path]) => path === '/api/v1/users?limit=1000')).toBe(false)
  },
)
it('requires explicit confirmation and sends only exact account fields', async () => {
  const close = vi.fn()
  const { fetch, notify } = setup(
    <UserMaintenance target={viewer} current={admin} onClose={close} />,
  )
  await userEvent.selectOptions(screen.getByLabelText('Papel da conta'), 'operator')
  expect(screen.getByText('Salvar conta')).toBeDisabled()
  await userEvent.click(screen.getByLabelText('Confirmo a alteração de viewer-fixture'))
  await userEvent.click(screen.getByText('Salvar conta'))
  await waitFor(() => expect(close).toHaveBeenCalled())
  const call = fetch.mock.calls.find(([, opts]) => opts?.method === 'PATCH')!
  expect(call[0]).toBe('/api/v1/users/viewer-id')
  expect(JSON.parse(call[1]!.body as string)).toEqual({
    role: 'operator',
    active: true,
    confirm: true,
  })
  expect(notify).toHaveBeenCalledWith('Conta atualizada; sessões afetadas encerradas.')
})
it('shows failure without closing or claiming success', async () => {
  const close = vi.fn()
  const { notify } = setup(
    <UserMaintenance target={viewer} current={admin} onClose={close} />,
    true,
  )
  await userEvent.click(screen.getByLabelText('Conta ativa'))
  await userEvent.click(screen.getByLabelText('Confirmo a alteração de viewer-fixture'))
  await userEvent.click(screen.getByText('Salvar conta'))
  await waitFor(() => expect(notify).toHaveBeenCalledWith('Conflito de conta', true))
  expect(close).not.toHaveBeenCalled()
  expect(screen.getByLabelText('Conta ativa')).not.toBeChecked()
})
it('separates own password, clears secrets after failure and never caches them', async () => {
  const { fetch, notify, cache } = setup(<AccountSettings user={viewer} />, true)
  await userEvent.click(screen.getByText('Trocar minha senha'))
  await userEvent.type(screen.getByLabelText('Senha atual'), 'current-fixture')
  await userEvent.type(screen.getByLabelText('Nova senha'), 'new-password-fixture')
  await userEvent.type(screen.getByLabelText('Confirmar nova senha'), 'new-password-fixture')
  await userEvent.click(screen.getByText('Confirmar troca de senha'))
  await waitFor(() => expect(notify).toHaveBeenCalledWith('Conflito de conta', true))
  expect(screen.getByLabelText('Senha atual')).toHaveValue('')
  expect(screen.getByLabelText('Nova senha')).toHaveValue('')
  const call = fetch.mock.calls.find(([path]) => path === '/api/v1/auth/password')!
  expect(JSON.parse(call[1]!.body as string)).toEqual({
    current_password: 'current-fixture',
    new_password: 'new-password-fixture',
    confirm: true,
  })
  expect(JSON.stringify(cache.getQueryCache().getAll())).not.toContain('new-password-fixture')
})
it('clears password on cancel and administrative reset never sends current password', async () => {
  const { fetch } = setup(<UserMaintenance target={viewer} current={admin} onClose={() => {}} />)
  await userEvent.click(screen.getByText('Redefinir senha desta conta'))
  let dialog = screen.getByRole('dialog', { name: 'Redefinir senha · viewer-fixture' })
  await userEvent.type(within(dialog).getByLabelText('Nova senha'), 'discarded-secret')
  await userEvent.click(within(dialog).getByLabelText('Fechar'))
  await userEvent.click(screen.getByText('Redefinir senha desta conta'))
  dialog = screen.getByRole('dialog', { name: 'Redefinir senha · viewer-fixture' })
  expect(within(dialog).getByLabelText('Nova senha')).toHaveValue('')
  expect(within(dialog).queryByLabelText('Senha atual')).not.toBeInTheDocument()
  await userEvent.type(within(dialog).getByLabelText('Nova senha'), 'new-password-fixture')
  await userEvent.type(
    within(dialog).getByLabelText('Confirmar nova senha'),
    'new-password-fixture',
  )
  await userEvent.click(within(dialog).getByText('Confirmar troca de senha'))
  await waitFor(() =>
    expect(fetch.mock.calls.some(([path]) => path === '/api/v1/users/viewer-id/password')).toBe(
      true,
    ),
  )
  const call = fetch.mock.calls.find(([path]) => path === '/api/v1/users/viewer-id/password')!
  expect(JSON.parse(call[1]!.body as string)).toEqual({
    new_password: 'new-password-fixture',
    confirm: true,
  })
})
it('confirms own session revocation and signals session end only after API success', async () => {
  const ended = vi.fn()
  addEventListener('aegis-session-ended', ended)
  try {
    const { fetch } = setup(<AccountSettings user={viewer} />)
    await screen.findByText('1 sessões vigentes')
    await userEvent.click(screen.getByText('Encerrar todas as sessões'))
    expect(ended).not.toHaveBeenCalled()
    await userEvent.click(screen.getByText('Confirmar encerramento'))
    await waitFor(() => expect(ended).toHaveBeenCalledOnce())
    const call = fetch.mock.calls.find(([path]) => path.endsWith('/sessions/revoke'))!
    expect(JSON.parse(call[1]!.body as string)).toEqual({ confirm: true })
  } finally {
    removeEventListener('aegis-session-ended', ended)
  }
})
