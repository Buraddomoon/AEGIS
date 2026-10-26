import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, Failure } from './lib'
import type { CatalogRelease, Page, Run } from './types'

interface Draft {
  mode: string
  catalog_release: string
  from: string
  before: string
}
const initial: Draft = { mode: 'demo', catalog_release: 'all', from: '', before: '' }

export function localTimestamp(value: string): string | null {
  if (!value) return null
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value))
    throw new Error('Data/hora local inválida.')
  const parsed = new Date(value)
  if (!Number.isFinite(parsed.getTime())) throw new Error('Data/hora local inválida.')
  const p = (number: number) => String(number).padStart(2, '0')
  const roundtrip = `${String(parsed.getFullYear()).padStart(4, '0')}-${p(parsed.getMonth() + 1)}-${p(parsed.getDate())}T${p(parsed.getHours())}:${p(parsed.getMinutes())}:${p(parsed.getSeconds())}`
  if (roundtrip.slice(0, value.length) !== value)
    throw new Error('Data/hora inexistente no fuso do navegador.')
  return parsed.toISOString()
}

function query(draft: Draft) {
  const params = new URLSearchParams({ mode: draft.mode, catalog_release: draft.catalog_release })
  const from = localTimestamp(draft.from),
    before = localTimestamp(draft.before)
  if (from && before && from >= before)
    throw new Error('O início deve ser anterior ao fim exclusivo.')
  if (from) params.set('requested_from', from)
  if (before) params.set('requested_before', before)
  return params.toString()
}

export function useCoverageFilters() {
  const [draft, setDraft] = useState(initial),
    [applied, setApplied] = useState(initial),
    [error, setError] = useState('')
  return {
    draft,
    setDraft,
    applied,
    error,
    dirty: JSON.stringify(draft) !== JSON.stringify(applied),
    query: query(applied),
    apply: () => {
      try {
        query(draft)
        setApplied({ ...draft })
        setError('')
        return true
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Recorte inválido.')
        return false
      }
    },
  }
}

async function releases() {
  const items: CatalogRelease[] = [],
    seen = new Set<string>()
  let total: number | null = null
  for (let page = 0; page < 100; page++) {
    const data = await api<Page<CatalogRelease>>(
      `/catalog/attack/releases?limit=100&offset=${items.length}`,
    )
    if (
      !Array.isArray(data.items) ||
      !Number.isInteger(data.total) ||
      data.total < 0 ||
      data.total > 10_000 ||
      (total !== null && total !== data.total)
    )
      throw new Error('Histórico do catálogo mudou ou está incompleto. Recarregue a página.')
    total = data.total
    for (const row of data.items) {
      if (seen.has(row.id)) throw new Error('Paginação de releases inconsistente.')
      seen.add(row.id)
      items.push(row)
    }
    if (items.length === total) return items
    if (!data.items.length || items.length > total) break
  }
  throw new Error('Histórico de releases incompleto ou acima do limite de consulta.')
}

export async function runOptions(query: string) {
  const items: Run[] = [],
    seen = new Set<string>()
  let total: number | null = null,
    scope: string | null = null
  for (let page = 0; page < 50; page++) {
    const data = await api<Page<Run> & { scope_sha256: string }>(
      `/coverage/runs?${query}&limit=100&offset=${items.length}`,
    )
    if (
      !Array.isArray(data.items) ||
      !/^[a-f0-9]{64}$/.test(data.scope_sha256 ?? '') ||
      !Number.isInteger(data.total) ||
      data.total < 0 ||
      data.total > 5000 ||
      (total !== null && total !== data.total) ||
      (scope !== null && scope !== data.scope_sha256)
    )
      throw new Error('Opções de execução mudaram durante a consulta. Recarregue o recorte.')
    total = data.total
    scope = data.scope_sha256
    for (const row of data.items) {
      if (seen.has(row.id)) throw new Error('Paginação de execuções inconsistente.')
      seen.add(row.id)
      items.push(row)
    }
    if (items.length === total) return { items, scope_sha256: scope }
    if (!data.items.length || items.length > total) break
  }
  throw new Error('Opções de execução incompletas; reduza o recorte.')
}

export function CoverageFilters({
  filters,
  busy,
  onApply,
  onChange,
  modeLabel = 'Modo dos indicadores',
}: {
  filters: ReturnType<typeof useCoverageFilters>
  busy: boolean
  onApply: () => void
  onChange?: () => void
  modeLabel?: string
}) {
  const catalog = useQuery({
    queryKey: ['analytics-catalog-releases'],
    queryFn: releases,
    retry: 1,
  })
  const change = (key: keyof Draft, value: string) => {
    filters.setDraft({ ...filters.draft, [key]: value })
    onChange?.()
  }
  return (
    <>
      <form
        className="coverage-filter-form"
        onSubmit={(e) => {
          e.preventDefault()
          if (filters.apply()) onApply()
        }}
      >
        <fieldset disabled={busy}>
          <label>
            Ambiente
            <select
              aria-label={modeLabel}
              value={filters.draft.mode}
              onChange={(e) => change('mode', e.target.value)}
            >
              <option value="demo">Demo · sintético</option>
              <option value="linux">Linux real</option>
            </select>
          </label>
          <label>
            Catálogo
            <select
              aria-label="Release dos indicadores"
              value={filters.draft.catalog_release}
              onChange={(e) => change('catalog_release', e.target.value)}
            >
              <option value="all">Todas · inclui legado desconhecido</option>
              <option value="current">Somente release atual</option>
              <option value="legacy">Legado · versão não registrada</option>
              {catalog.data?.map((r) => (
                <option key={r.id} value={r.id}>
                  Enterprise v{r.dataset_version} · {r.id.slice(0, 12)} ·{' '}
                  {r.provenance === 'bundled' ? 'inicial' : 'commit oficial'}
                </option>
              ))}
            </select>
          </label>
          <label>
            Solicitadas a partir de
            <input
              type="datetime-local"
              step="1"
              aria-label="Solicitadas a partir de"
              value={filters.draft.from}
              onChange={(e) => change('from', e.target.value)}
            />
          </label>
          <label>
            Antes de · exclusivo
            <input
              type="datetime-local"
              step="1"
              aria-label="Solicitadas antes de"
              value={filters.draft.before}
              onChange={(e) => change('before', e.target.value)}
            />
          </label>
          <button className="button primary" type="submit">
            Aplicar recorte
          </button>
        </fieldset>
      </form>
      <p className="muted-text analysis-filter-caption">
        Data da solicitação · início inclusivo/fim exclusivo · fuso do navegador:{' '}
        {Intl.DateTimeFormat().resolvedOptions().timeZone}. Exportação registra UTC.
      </p>
      {filters.dirty && (
        <div className="notice warning">
          Filtros alterados. Aplique o recorte; os indicadores abaixo ainda pertencem ao último
          recorte aplicado.
        </div>
      )}
      {filters.error && <Failure error={new Error(filters.error)} />}
      {catalog.error && <Failure error={catalog.error} />}
    </>
  )
}
