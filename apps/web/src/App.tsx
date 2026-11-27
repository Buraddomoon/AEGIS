import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  BookOpen,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  Monitor,
  Search,
  FileChartColumn,
  FlaskConical,
  Grid2X2,
  Layers,
  LayoutDashboard,
  LogOut,
  Menu,
  Radio,
  Settings2,
  Shield,
  ShieldCheck,
  Workflow,
  X,
} from 'lucide-react'
import { api, Empty, Go, Loading, NoticeContext, useData } from './lib'
import type { User } from './types'
import { Catalog, TestLibrary } from './Catalog'
import { Campaigns, Executions, ExecutionDetail, CoveragePage, Reports } from './Operations'
import { Laboratories, Rules, Settings } from './Management'
import { Scheduling } from './Scheduling'

import Overview from './Overview'
import Login from './Login'
import { Brand } from './Brand'
import { QuickNavigation } from './QuickNavigation'

const navigation = [
  {
    group: 'PRINCIPAL',
    items: [
      { id: 'overview', label: 'Visão geral', icon: LayoutDashboard },
      { id: 'attack', label: 'Matriz ATT&CK', icon: Grid2X2 },
    ],
  },
  {
    group: 'OPERAÇÕES',
    items: [
      { id: 'tests', label: 'Biblioteca de testes', icon: BookOpen },
      { id: 'campaigns', label: 'Campanhas', icon: Layers },
      { id: 'executions', label: 'Execuções', icon: Activity },
      { id: 'schedules', label: 'Agendamentos', icon: CalendarClock },
    ],
  },
  {
    group: 'DETECÇÃO',
    items: [
      { id: 'coverage', label: 'Cobertura de detecção', icon: ShieldCheck },
      { id: 'rules', label: 'Regras Sigma', icon: Workflow },
      { id: 'reports', label: 'Relatórios', icon: FileChartColumn },
    ],
  },
  {
    group: 'AMBIENTE',
    items: [
      { id: 'labs', label: 'Laboratórios', icon: FlaskConical },
      { id: 'settings', label: 'Configurações', icon: Settings2 },
    ],
  },
]

export default function App() {
  const [route, setRoute] = useState(location.hash.slice(1) || 'overview'),
    [mobile, setMobile] = useState(false)
  const sidebarRef = useRef<HTMLElement>(null)
  const mainRef = useRef<HTMLElement>(null)
  const menuRef = useRef<HTMLButtonElement>(null)
  const [quickNav, setQuickNav] = useState(false)
  const [notice, setNotice] = useState<{ message: string; error: boolean } | null>(null)
  const [sessionMessage, setSessionMessage] = useState('')
  const user = useData<User>('/auth/me', 30000),
    cache = useQueryClient()
  useEffect(() => {
    const ended = (event: Event) => {
      // An anonymous response is not a session transition. Keep the observed
      // identity query attached so a subsequent successful login can update it.
      if (!cache.getQueryData(['/auth/me'])) return
      setSessionMessage((event as CustomEvent<string>).detail)
      setMobile(false)
      setQuickNav(false)
      setNotice(null)
      void cache.cancelQueries()
      cache.removeQueries({ predicate: (query) => query.queryKey[0] !== '/auth/me' })
      cache.setQueryData(['/auth/me'], null)
    }
    addEventListener('aegis-session-ended', ended)
    return () => removeEventListener('aegis-session-ended', ended)
  }, [cache])
  useEffect(() => {
    const update = () => {
      setRoute(location.hash.slice(1) || 'overview')
      setMobile(false)
    }
    addEventListener('hashchange', update)
    return () => removeEventListener('hashchange', update)
  }, [])
  useEffect(() => {
    if (!notice) return
    const timeout = setTimeout(() => setNotice(null), 7000)
    return () => clearTimeout(timeout)
  }, [notice])
  useEffect(() => {
    if (!user.data) return
    const shortcut = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setQuickNav((open) => !open)
      }
    }
    addEventListener('keydown', shortcut)
    return () => removeEventListener('keydown', shortcut)
  }, [!!user.data])
  useEffect(() => {
    if (!mobile) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const focusable = () =>
      Array.from(
        sidebarRef.current?.querySelectorAll<HTMLElement>('a[href], button:not([disabled])') ?? [],
      )
    focusable()[0]?.focus()
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobile(false)
      if (event.key !== 'Tab') return
      const items = focusable(),
        first = items[0],
        last = items.at(-1)
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }
    const desktop = window.matchMedia('(min-width: 851px)')
    const resize = () => {
      if (desktop.matches) setMobile(false)
    }
    desktop.addEventListener('change', resize)
    addEventListener('keydown', keydown)
    return () => {
      document.body.style.overflow = previousOverflow
      removeEventListener('keydown', keydown)
      desktop.removeEventListener('change', resize)
      menuRef.current?.focus()
    }
  }, [mobile])
  useEffect(() => {
    if (user.data) {
      mainRef.current?.focus({ preventScroll: true })
      window.scrollTo({ top: 0 })
    }
  }, [route, user.data?.id])
  if (user.isLoading)
    return (
      <div className="fullscreen">
        <Loading />
      </div>
    )
  if (!user.data)
    return (
      <Login
        message={sessionMessage}
        onLogin={async (authenticatedUser) => {
          await cache.cancelQueries()
          cache.removeQueries({ predicate: (query) => query.queryKey[0] !== '/auth/me' })
          cache.setQueryData(['/auth/me'], authenticatedUser)
          setSessionMessage('')
        }}
      />
    )
  const page = route.split(/[/?]/)[0],
    title = navigation.flatMap((g) => g.items).find((n) => n.id === page)?.label ?? 'Execução'
  const logout = async () => {
    await api('/auth/logout', { method: 'POST' })
    cache.clear()
    location.hash = 'overview'
    location.reload()
  }
  return (
    <NoticeContext.Provider value={(message, error = false) => setNotice({ message, error })}>
      <div className="app-shell">
        <a
          className="skip-link"
          href="#main"
          onClick={(event) => {
            event.preventDefault()
            mainRef.current?.focus()
          }}
        >
          Pular para o conteúdo
        </a>
        {mobile && (
          <button
            className="mobile-backdrop"
            aria-label="Fechar navegação"
            tabIndex={-1}
            onClick={() => setMobile(false)}
          />
        )}
        <aside
          ref={sidebarRef}
          id="workspace-navigation"
          className={`sidebar ${mobile ? 'mobile-open' : ''}`}
          role={mobile ? 'dialog' : undefined}
          aria-modal={mobile || undefined}
          aria-label="Menu do workspace"
        >
          <button
            className="icon-button sidebar-close"
            aria-label="Fechar menu"
            onClick={() => setMobile(false)}
          >
            <X size={20} />
          </button>
          <a href="#overview" aria-label="AEGIS — Visão geral" onClick={() => setMobile(false)}>
            <Brand subtitle />
          </a>
          <div className="workspace">
            <span className="workspace-avatar">A</span>
            <div>
              Workspace local<small>Validação de detecção</small>
            </div>
            <Shield size={15} className="workspace-lock" aria-hidden="true" />
          </div>
          <nav aria-label="Navegação principal">
            {navigation.map((group) => (
              <div className="nav-group" key={group.group}>
                <p>{group.group}</p>
                {group.items.map((item) => (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    onClick={() => setMobile(false)}
                    className={`nav-item ${page === item.id ? 'active' : ''}`}
                    aria-current={page === item.id ? 'page' : undefined}
                  >
                    <item.icon size={18} />
                    {item.label}
                    {page === item.id && <span className="nav-active-dot" />}
                  </a>
                ))}
              </div>
            ))}
          </nav>
          <div className="sidebar-note">
            <ShieldCheck size={20} />
            <strong>Evidências, em primeiro lugar.</strong>
            <p>Simule. Observe. Valide. Evolua.</p>
            <span>
              ÆGIS <span className="version">v0.2.0</span>
            </span>
          </div>
          <div className="profile">
            <span className="avatar">{user.data.username.slice(0, 2).toUpperCase()}</span>
            <div>
              {user.data.username}
              <small>
                {user.data.role === 'administrator'
                  ? 'Administrador'
                  : user.data.role === 'operator'
                    ? 'Operador'
                    : 'Visualizador'}
              </small>
            </div>
            <button
              onClick={() =>
                void logout().catch((e) => setNotice({ message: String(e), error: true }))
              }
              className="icon-button"
              aria-label="Sair"
            >
              <LogOut size={17} />
            </button>
          </div>
        </aside>
        <div className="main-shell" inert={mobile}>
          <header className="topbar">
            <div className="breadcrumb">
              <button
                ref={menuRef}
                className="icon-button mobile-menu"
                aria-label={mobile ? 'Fechar menu' : 'Abrir menu'}
                aria-expanded={mobile}
                aria-controls="workspace-navigation"
                onClick={() => setMobile(!mobile)}
              >
                <Menu size={20} />
              </button>
              <Shield size={16} />
              <span>Console</span>
              <ChevronRight size={14} />
              <strong>{title}</strong>
            </div>
            <div className="topbar-actions">
              <button
                className="quick-nav-trigger"
                onClick={() => setQuickNav(true)}
                aria-label="Buscar página"
              >
                <Search size={16} />
                <span>Ir para uma página</span>
                <kbd>Ctrl K</kbd>
              </button>
              <span className="local-pill">
                <Monitor size={14} />
                <span>Ambiente local</span>
              </span>
            </div>
          </header>
          <main id="main" ref={mainRef} tabIndex={-1}>
            {page === 'overview' ? (
              <Overview user={user.data} />
            ) : page === 'attack' ? (
              <Catalog canReview={user.data.role === 'administrator'} />
            ) : page === 'tests' ? (
              <TestLibrary user={user.data} />
            ) : page === 'campaigns' ? (
              <Campaigns user={user.data} />
            ) : page === 'executions' && route.split('/')[1] ? (
              <ExecutionDetail id={route.split('/')[1]} user={user.data} />
            ) : page === 'executions' ? (
              <Executions />
            ) : page === 'schedules' ? (
              <Scheduling user={user.data} id={route.split('/')[1]} key={route} />
            ) : page === 'coverage' ? (
              <CoveragePage />
            ) : page === 'reports' ? (
              <Reports />
            ) : page === 'rules' ? (
              <Rules user={user.data} />
            ) : page === 'labs' ? (
              <Laboratories user={user.data} />
            ) : page === 'settings' ? (
              <Settings user={user.data} />
            ) : (
              <Empty title="Página não encontrada">
                <Go to="overview">Voltar à visão geral</Go>
              </Empty>
            )}
          </main>
          <footer>
            ÆGIS · Purple Team Automation & Detection Validation
            <span>Uso exclusivo em ambientes autorizados</span>
          </footer>
        </div>
        {quickNav && <QuickNavigation groups={navigation} onClose={() => setQuickNav(false)} />}
        {notice && (
          <div className={`toast ${notice.error ? 'danger' : ''}`} role="alert">
            {notice.error ? <Radio size={18} /> : <CheckCircle2 size={18} />}
            <span>{notice.message}</span>
            <button
              className="icon-button"
              aria-label="Dispensar mensagem"
              onClick={() => setNotice(null)}
            >
              <X size={17} />
            </button>
          </div>
        )}
      </div>
    </NoticeContext.Provider>
  )
}
