import { createContext, useContext, useRef, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, ArrowRight, Check, LoaderCircle, X } from 'lucide-react'

export function csrf() {
  return (
    document.cookie
      .split('; ')
      .find((s) => s.startsWith('aegis_csrf='))
      ?.split('=')[1] ?? ''
  )
}
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-Aegis-Request': 'browser',
      'X-CSRF-Token': csrf(),
      ...options.headers,
    },
  })
  if (!response.ok) {
    const error = await response.json().catch(() => null)
    throw new Error(error?.error?.message ?? `A API retornou HTTP ${response.status}`)
  }
  return response.status === 204 ? (undefined as T) : response.json()
}
export function useData<T>(path: string, interval: number | false = false) {
  return useQuery({
    queryKey: [path],
    queryFn: () => api<T>(path),
    refetchInterval: interval,
    retry: 1,
  })
}
export function navigate(path: string) {
  window.location.hash = path
}
export function date(value: string | null) {
  return value
    ? new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(
        new Date(value),
      )
    : '—'
}
export const labels: Record<string, string> = {
  DETECTED: 'Detectado',
  OBSERVED_NOT_ALERTED: 'Observado sem alerta',
  NO_TELEMETRY: 'Sem telemetria',
  INCONCLUSIVE: 'Inconclusivo',
  EXECUTION_FAILED: 'Falha na execução',
  NOT_TESTED: 'Não avaliado',
  CREATED: 'Criado',
  PENDING_APPROVAL: 'Aguardando aprovação',
  QUEUED: 'Na fila',
  PREPARING: 'Preparando',
  RUNNING: 'Executando',
  COLLECTING: 'Coletando',
  VALIDATING: 'Validando',
  CLEANING_UP: 'Limpando',
  COMPLETED: 'Concluído',
  REJECTED: 'Rejeitado',
  FAILED: 'Falhou',
  TIMED_OUT: 'Tempo esgotado',
  CANCELLED: 'Cancelado',
  CLEANUP_FAILED: 'Falha de limpeza',
  DISPATCHED: 'Execução emitida',
  ACTIVE: 'Ativo',
  PAUSED: 'Pausado',
  REVOKED: 'Revogado',
  EXPIRED: 'Expirado',
  EXHAUSTED: 'Limite encerrado',
  INVALIDATED: 'Invalidado',
  SKIPPED_LATE: 'Descartado por atraso',
  SKIPPED_BUSY: 'Laboratório ocupado',
  disconnected: 'Desconectado',
  connected: 'mTLS verificado',
  configured_unverified: 'Configurado · não verificado',
  synthetic: 'Sintético',
  administrator: 'Administrador',
  operator: 'Operador',
  viewer: 'Visualizador',
}
export const terminal = [
  'COMPLETED',
  'REJECTED',
  'FAILED',
  'TIMED_OUT',
  'CANCELLED',
  'CLEANUP_FAILED',
]
export function Badge({ value }: { value: string }) {
  return (
    <span className={`badge status-${value}`}>
      <span className="status-dot" />
      {labels[value] ?? value}
    </span>
  )
}
export function Empty({
  title = 'Nenhum resultado ainda',
  children,
}: {
  title?: string
  children?: ReactNode
}) {
  return (
    <div className="empty">
      <span className="empty-icon">◇</span>
      <h3>{title}</h3>
      <p>{children ?? 'Os dados aparecerão aqui após a primeira execução.'}</p>
    </div>
  )
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={18} /> Carregando dados…
    </div>
  )
}
export function Failure({ error }: { error: Error }) {
  return (
    <div className="notice danger" role="alert">
      <AlertCircle size={18} />
      {error.message}
    </div>
  )
}
export function Panel({
  title,
  subtitle,
  action,
  children,
  className = '',
}: {
  title?: string
  subtitle?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <header className="panel-heading">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}
export function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  )
}
export function Modal({
  title,
  onClose,
  children,
}: {
  title: string
  onClose: () => void
  children: ReactNode
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    ref.current?.showModal()
    return () => ref.current?.close()
  }, [])
  return (
    <dialog ref={ref} onCancel={onClose} className="modal" aria-label={title}>
      <div className="modal-heading">
        <h2>{title}</h2>
        <button className="icon-button" aria-label="Fechar" onClick={onClose}>
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  )
}
export const NoticeContext = createContext<(message: string, error?: boolean) => void>(() => {})
export function useAction() {
  const [busy, setBusy] = useState(false),
    notify = useContext(NoticeContext),
    cache = useQueryClient()
  const run = async (task: () => Promise<unknown>, message = 'Operação concluída.') => {
    setBusy(true)
    try {
      await task()
      await cache.invalidateQueries()
      notify(message)
    } catch (error) {
      notify(error instanceof Error ? error.message : 'Falha na operação.', true)
    } finally {
      setBusy(false)
    }
  }
  return { busy, run }
}
export function Submit({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <button type="submit" className="button primary" disabled={busy}>
      {busy ? <LoaderCircle size={17} className="spin" /> : <Check size={17} />} {children}
    </button>
  )
}
export function Go({ to, children }: { to: string; children: ReactNode }) {
  return (
    <a className="text-link" href={`#${to}`}>
      {children}
      <ArrowRight size={15} />
    </a>
  )
}
export async function downloadReport(runId: string, format: 'json' | 'html') {
  const response = await fetch(`/api/v1/reports/${runId}?format=${format}`, {
    credentials: 'same-origin',
  })
  if (!response.ok) throw new Error('Não foi possível exportar o relatório.')
  const blob = await response.blob(),
    url = URL.createObjectURL(blob),
    link = document.createElement('a')
  link.href = url
  link.download = `aegis-${runId}.${format}`
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
