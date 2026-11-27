import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FileChartColumn, Layers } from 'lucide-react'
import Login from './Login'
import Overview, { OutcomeSummary } from './Overview'
import { QuickNavigation } from './QuickNavigation'
import App from './App'

beforeAll(() => {
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
  window.location.hash = ''
})
const json = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body })
const coverage = {
  catalogued_techniques: null,
  evaluated_techniques: null,
  total_runs: 0,
  completed_tests: 0,
  valid_tests: 0,
  detected_percentage: null,
  outcomes: {},
  trend: [],
  denominator: 'Nenhum teste válido.',
  limitation: 'Dados sintéticos.',
}
function queryRender(element: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return render(<QueryClientProvider client={client}>{element}</QueryClientProvider>)
}

describe('Workspace access and navigation', () => {
  it('reveals a password without submitting the form or losing its value', async () => {
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    render(<Login onLogin={vi.fn()} />)
    const password = screen.getByLabelText('Senha')
    await userEvent.type(password, 'local-test-password')
    await userEvent.click(screen.getByRole('button', { name: 'Mostrar senha' }))
    expect(password).toHaveAttribute('type', 'text')
    expect(password).toHaveValue('local-test-password')
    expect(screen.getByRole('button', { name: 'Ocultar senha' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    await userEvent.click(screen.getByRole('button', { name: 'Ocultar senha' }))
    expect(password).toHaveAttribute('type', 'password')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('keeps a failed login on the form and announces the API error', async () => {
    const onLogin = vi.fn()
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(json({ error: { message: 'Credenciais inválidas' } }, 401)),
    )
    render(<Login onLogin={onLogin} />)
    await userEvent.type(screen.getByLabelText('Usuário'), 'preview')
    await userEvent.type(screen.getByLabelText('Senha'), 'wrong-password')
    await userEvent.click(screen.getByRole('button', { name: 'Entrar no workspace' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Credenciais inválidas')
    expect(onLogin).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Entrar no workspace' })).toBeEnabled()
  })

  it('searches page names without requiring Portuguese accents and supports Enter', async () => {
    const close = vi.fn()
    render(
      <QuickNavigation
        groups={[
          {
            group: 'OPERAÇÕES',
            items: [
              { id: 'campaigns', label: 'Campanhas', icon: Layers },
              { id: 'reports', label: 'Relatórios', icon: FileChartColumn },
            ],
          },
        ]}
        onClose={close}
      />,
    )
    const search = screen.getByRole('searchbox', { name: 'Pesquisar páginas' })
    expect(search).toHaveFocus()
    await userEvent.type(search, 'relatorio')
    expect(screen.getByRole('link', { name: /Relatórios/ })).toHaveAttribute('href', '#reports')
    expect(screen.queryByRole('link', { name: /Campanhas/ })).not.toBeInTheDocument()
    await userEvent.keyboard('{Enter}')
    expect(window.location.hash).toBe('#reports')
    expect(close).toHaveBeenCalledOnce()
  })

  it('keeps an unmatched search explicit and does not navigate on Enter', async () => {
    const close = vi.fn()
    render(<QuickNavigation groups={[]} onClose={close} />)
    await userEvent.type(screen.getByRole('searchbox'), 'missing{Enter}')
    expect(screen.getByText(/Nenhuma página encontrada/)).toBeInTheDocument()
    expect(close).not.toHaveBeenCalled()
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { bubbles: true, cancelable: true }))
    expect(close).toHaveBeenCalledOnce()
  })

  it('does not claim an expired session on the first unauthenticated visit', async () => {
    vi.stubGlobal('scrollTo', vi.fn())
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(json({ error: { message: 'Autenticação necessária' } }, 401)),
    )
    queryRender(<App />)
    expect(await screen.findByRole('form', { name: 'Acessar workspace' })).toBeInTheDocument()
    expect(
      screen.queryByText('Sessão expirada ou revogada. Entre novamente.'),
    ).not.toBeInTheDocument()
  })

  it('preserves the session-expired notice when concurrent requests report revocation', async () => {
    vi.stubGlobal('scrollTo', vi.fn())
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        json(
          url.endsWith('/auth/me')
            ? { id: 'operator', username: 'operator', role: 'operator', active: true }
            : url.endsWith('/coverage')
              ? coverage
              : url.endsWith('/connectors')
                ? { items: [], worker_online: false }
                : { items: [], total: 0 },
        ),
      ),
    )
    queryRender(<App />)
    await screen.findByRole('navigation', { name: 'Navegação principal' })
    for (let index = 0; index < 2; index++)
      fireEvent(
        window,
        new CustomEvent('aegis-session-ended', {
          detail: 'Sessão expirada ou revogada. Entre novamente.',
        }),
      )
    expect(
      await screen.findByText('Sessão expirada ou revogada. Entre novamente.'),
    ).toBeInTheDocument()
  })
})

describe('Overview keeps unavailable and synthetic data explicit', () => {
  it('does not turn connector errors into an offline worker or a success claim', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        url.endsWith('/coverage')
          ? json(coverage)
          : url.endsWith('/connectors')
            ? json({ error: { message: 'Integrações indisponíveis' } }, 503)
            : json({ items: [], total: 0 }),
      ),
    )
    queryRender(
      <Overview user={{ id: 'viewer', username: 'viewer', role: 'viewer', active: true }} />,
    )
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2), { timeout: 4000 })
    expect(screen.queryByText('Worker sem heartbeat recente')).not.toBeInTheDocument()
    expect(screen.queryByText('Worker disponível')).not.toBeInTheDocument()
    expect(screen.getByText('Catálogo atual indisponível')).toBeInTheDocument()
    expect(screen.queryByText('0%')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Nova campanha' })).not.toBeInTheDocument()
  })

  it('includes failed executions in the result breakdown without relabeling them', () => {
    const { container } = render(
      <OutcomeSummary outcomes={{ DETECTED: 2, EXECUTION_FAILED: 3, INCONCLUSIVE: 1 }} />,
    )
    expect(container.querySelector('.outcome-ring strong')).toHaveTextContent('6')
    expect(screen.getByText('Falha na execução')).toBeInTheDocument()
    expect(screen.getByText('Simulação sintética')).toBeInTheDocument()
  })
})
