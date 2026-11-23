import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { localTimestamp, releases } from './CoverageFilters'
import { api, date, downloadFile, Failure, Loading, Panel } from './lib'

interface Lab {
  id: string
  name: string
  kind: 'demo' | 'linux'
}
interface Cut {
  laboratory_id: string
  catalog_release: string
  from: string
  before: string
}
interface Side {
  laboratory_id: string
  synthetic: boolean
  total_runs: number
  valid_tests: number
  detected_tests: number
  excluded_tests: number
  detected_percentage: number | null
  denominator: string
  selection: Record<string, string | null>
  cohorts: { context_sha256: string; context: Record<string, unknown>; run_ids: string[] }[]
  members: unknown[]
}
export interface EnvironmentReport {
  kind: string
  report_version: string
  integrity_sha256: string
  snapshot_at: string
  before: Side
  after: Side
  comparison: {
    classification: 'equivalent' | 'descriptive' | 'incomparable'
    reasons: string[]
    detected_rate_delta_percentage_points: number | null
    limitation: string
    context_differences: { field: string; before: unknown; after: unknown }[] | null
  }
}
const initial: Cut = { laboratory_id: '', catalog_release: 'all', from: '', before: '' }
const reasons: Record<string, string> = {
  unknown_context: 'Configuração histórica incompleta',
  unknown_catalog_context: 'Release ATT&CK desconhecida',
  unknown_test_context: 'Definição ou versão de teste desconhecida',
  unknown_defensive_source_or_runner: 'Fonte defensiva ou runner desconhecido',
  incomplete_runs: 'Há execuções não concluídas',
  incomplete_test_executions: 'Há testes não concluídos',
  execution_manifest_mismatch: 'Testes não correspondem ao manifesto',
  missing_validation_results: 'Faltam resultados de validação',
  origin_mismatch: 'Origem sintética/real ou identidade contraditória; taxa suprimida',
  validation_logic_mismatch: 'Versão da lógica divergente',
  partial_or_excluded_results: 'Há resultados excluídos ou coleta incompleta',
  heterogeneous_contexts: 'Há configurações diferentes no mesmo lado',
  empty_denominator: 'Sem testes válidos',
  scope_integrity_mismatch: 'Hash do scope diverge do conteúdo',
  different_modes: 'Demo e real têm origens distintas; taxas não são combinadas',
  different_recorded_contexts: 'Configurações históricas diferentes',
  different_test_frequencies: 'Testes ou frequências diferentes entre os lados',
}
function reason(value: string) {
  const parts = value.split(':'),
    key = parts.at(-1) ?? value
  return `${parts.length > 1 ? (parts[0] === 'before' ? 'A: ' : 'B: ') : ''}${reasons[key] ?? key}`
}
function parameters(cuts: Cut[], labs: Lab[]) {
  const params = new URLSearchParams()
  cuts.forEach((cut, i) => {
    const side = i === 0 ? 'before' : 'after',
      lab = labs.find((l) => l.id === cut.laboratory_id)
    if (!lab || !['demo', 'linux'].includes(lab.kind))
      throw new Error('Selecione um laboratório disponível por lado.')
    params.set(`${side}_laboratory_id`, lab.id)
    params.set(`${side}_mode`, lab.kind)
    params.set(`${side}_catalog_release`, cut.catalog_release)
    const from = localTimestamp(cut.from),
      before = localTimestamp(cut.before)
    if (from && before && from >= before)
      throw new Error('O início deve ser anterior ao fim exclusivo.')
    if (from) params.set(`${side}_requested_from`, from)
    if (before) params.set(`${side}_requested_before`, before)
  })
  if (cuts[0].laboratory_id === cuts[1].laboratory_id)
    throw new Error('Selecione laboratórios distintos.')
  return params
}
export function matchingReport(report: EnvironmentReport, params: URLSearchParams) {
  if (
    report.kind !== 'environment-comparison' ||
    report.report_version !== 'aegis-environment-comparison/1' ||
    !/^[a-f0-9]{64}$/.test(report.integrity_sha256) ||
    !Number.isFinite(Date.parse(report.snapshot_at)) ||
    !['equivalent', 'descriptive', 'incomparable'].includes(report.comparison?.classification) ||
    !Array.isArray(report.comparison.reasons) ||
    (report.comparison.context_differences !== null &&
      !Array.isArray(report.comparison.context_differences))
  )
    return false
  return (['before', 'after'] as const).every((side) => {
    const c = report[side]
    if (!c || c.laboratory_id !== params.get(`${side}_laboratory_id`) || !c.selection) return false
    return (
      ['laboratory_id', 'mode', 'catalog_release', 'requested_from', 'requested_before'].every(
        (key) => {
          const expected = params.get(`${side}_${key}`),
            actual = c.selection[key] ?? null
          return key.startsWith('requested_') && expected && actual
            ? Date.parse(expected) === Date.parse(actual)
            : expected === actual
        },
      ) &&
      Array.isArray(c.cohorts) &&
      Array.isArray(c.members) &&
      c.synthetic === (params.get(`${side}_mode`) === 'demo')
    )
  })
}

export function EnvironmentComparison() {
  const [open, setOpen] = useState(false)
  return (
    <Panel
      title="Comparação entre laboratórios"
      subtitle="Dois recortes históricos explícitos; somente leitura, sem iniciar testes ou consultar sensores."
    >
      <button className="button" onClick={() => setOpen(!open)}>
        {open ? 'Fechar comparação de laboratórios' : 'Escolher dois laboratórios'}
      </button>
      {open && <EnvironmentForm />}
    </Panel>
  )
}
function EnvironmentForm() {
  const labs = useQuery({
      queryKey: ['environment-comparison-labs'],
      queryFn: () => api<{ items: Lab[] }>('/labs'),
    }),
    catalog = useQuery({ queryKey: ['analytics-catalog-releases'], queryFn: releases }),
    [cuts, setCuts] = useState<Cut[]>([{ ...initial }, { ...initial }]),
    [report, setReport] = useState<EnvironmentReport | null>(null),
    [applied, setApplied] = useState(''),
    [error, setError] = useState<Error | null>(null),
    [busy, setBusy] = useState(false),
    revision = useRef(0),
    pending = useRef<AbortController | null>(null)
  useEffect(
    () => () => {
      pending.current?.abort()
    },
    [],
  )
  const change = (i: number, key: keyof Cut, value: string) => {
    revision.current++
    pending.current?.abort()
    setCuts(cuts.map((c, n) => (n === i ? { ...c, [key]: value } : c)))
    setReport(null)
    setApplied('')
    setError(null)
  }
  const ready = !busy && !labs.error && !catalog.error && !!labs.data && !!catalog.data
  const load = async () => {
    const ticket = ++revision.current
    pending.current = new AbortController()
    setReport(null)
    setError(null)
    setBusy(true)
    try {
      const params = parameters(cuts, labs.data?.items ?? [])
      const value = await api<EnvironmentReport>(`/coverage/environments?${params}`, {
        signal: pending.current.signal,
      })
      if (!matchingReport(value, params))
        throw new Error('Resposta incompatível com os dois recortes; consulte novamente.')
      if (ticket === revision.current) {
        setReport(value)
        setApplied(params.toString())
      }
    } catch (e) {
      if (ticket === revision.current)
        setError(e instanceof Error ? e : new Error('Falha na comparação.'))
    } finally {
      setBusy(false)
    }
  }
  const exportReport = async (format: string) => {
    if (!report) return
    setBusy(true)
    setError(null)
    const ticket = revision.current
    pending.current = new AbortController()
    try {
      const params = new URLSearchParams(applied)
      params.set('snapshot_at', report.snapshot_at)
      params.set('expected_snapshot_sha256', report.integrity_sha256)
      params.set('format', format)
      await downloadFile(
        `/coverage/environments/report?${params}`,
        `aegis-laboratorios-${report.integrity_sha256.slice(0, 12)}.${format}`,
        pending.current.signal,
      )
    } catch (e) {
      if (ticket === revision.current) {
        setReport(null)
        setError(e instanceof Error ? e : new Error('Falha na exportação.'))
      }
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="analysis-export-body">
      {(labs.isLoading || catalog.isLoading || busy) && <Loading />}
      {labs.error && <Failure error={labs.error} />}
      {catalog.error && <Failure error={catalog.error} />}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (ready) void load()
        }}
      >
        <div className="gap-grid">
          {cuts.map((cut, i) => (
            <fieldset key={i} aria-label={`Recorte ${i === 0 ? 'A' : 'B'}`}>
              <legend>Recorte {i === 0 ? 'A' : 'B'}</legend>
              <label>
                Laboratório
                <select
                  aria-label={`Laboratório ${i === 0 ? 'A' : 'B'}`}
                  required
                  value={cut.laboratory_id}
                  onChange={(e) => change(i, 'laboratory_id', e.target.value)}
                >
                  <option value="">Selecione um laboratório</option>
                  {labs.data?.items
                    .filter((l) => ['demo', 'linux'].includes(l.kind))
                    .map((l) => (
                      <option key={l.id} value={l.id}>
                        {l.name} · {l.kind === 'demo' ? 'Demo sintético' : 'Linux real'}
                      </option>
                    ))}
                </select>
              </label>
              <label>
                Catálogo
                <select
                  aria-label={`Release ${i === 0 ? 'A' : 'B'}`}
                  value={cut.catalog_release}
                  onChange={(e) => change(i, 'catalog_release', e.target.value)}
                >
                  <option value="all">Todas · inclui legado</option>
                  <option value="current">Somente atual</option>
                  <option value="legacy">Legado · desconhecido</option>
                  {catalog.data?.map((r) => (
                    <option key={r.id} value={r.id}>
                      Enterprise v{r.dataset_version} · {r.id.slice(0, 12)}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Solicitadas a partir de
                <input
                  aria-label={`Início ${i === 0 ? 'A' : 'B'}`}
                  type="datetime-local"
                  step="1"
                  value={cut.from}
                  onChange={(e) => change(i, 'from', e.target.value)}
                />
              </label>
              <label>
                Antes de · exclusivo
                <input
                  aria-label={`Fim ${i === 0 ? 'A' : 'B'}`}
                  type="datetime-local"
                  step="1"
                  value={cut.before}
                  onChange={(e) => change(i, 'before', e.target.value)}
                />
              </label>
            </fieldset>
          ))}
        </div>
        <p className="muted-text">
          Data da solicitação · fuso do navegador:{' '}
          {Intl.DateTimeFormat().resolvedOptions().timeZone}. Alterar qualquer filtro descarta a
          comparação e os exports anteriores.
        </p>
        <button
          className="button primary"
          disabled={
            !ready ||
            cuts.some((c) => !c.laboratory_id) ||
            cuts[0].laboratory_id === cuts[1].laboratory_id
          }
        >
          Consultar laboratórios
        </button>
      </form>
      {error && <Failure error={error} />}
      {report && !labs.error && !catalog.error && (
        <>
          <div
            className={`notice ${report.comparison.classification === 'equivalent' ? '' : 'warning'}`}
          >
            <div>
              <strong>
                {report.comparison.classification === 'equivalent'
                  ? 'Equivalência limitada aos registros'
                  : report.comparison.classification === 'descriptive'
                    ? 'Comparação descritiva · sem delta'
                    : 'Recortes incomparáveis · sem delta'}
              </strong>
              <p>{report.comparison.limitation}</p>
              {!!report.comparison.reasons.length && (
                <ul>
                  {report.comparison.reasons.map((r) => (
                    <li key={r}>{reason(r)}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Medida</th>
                  <th>Recorte A</th>
                  <th>Recorte B</th>
                </tr>
              </thead>
              <tbody>
                {(
                  [
                    'laboratory_id',
                    'total_runs',
                    'detected_tests',
                    'valid_tests',
                    'excluded_tests',
                    'detected_percentage',
                  ] as const
                ).map((key, i) => (
                  <tr key={key}>
                    <td>
                      {
                        [
                          'Laboratório (ID)',
                          'Execuções',
                          'Detectados',
                          'Testes válidos',
                          'Excluídos da taxa',
                          'Taxa neste recorte (%)',
                        ][i]
                      }
                    </td>
                    {[report.before, report.after].map((c, n) => (
                      <td key={n}>{c[key] ?? 'Não calculada'}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            Delta em pontos percentuais:{' '}
            {report.comparison.detected_rate_delta_percentage_points ?? 'não calculado'}. Diferença
            não demonstra melhoria causal.
          </p>
          <p>
            Snapshot consultado: {date(report.snapshot_at)} · {report.before.denominator}
          </p>
          <details className="scope-details">
            <summary>Diferenças de configuração registradas</summary>
            {report.comparison.context_differences === null ? (
              <p>Há contextos vazios ou múltiplos. Inspecione cada configuração por lado abaixo.</p>
            ) : report.comparison.context_differences.length === 0 ? (
              <p>
                Nenhuma diferença nas configurações registradas. Identidades de laboratório/ativo
                estão nos membros; igualdade física não atestada.
              </p>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Campo</th>
                      <th>Recorte A</th>
                      <th>Recorte B</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.comparison.context_differences.map((d) => (
                      <tr key={d.field}>
                        <td>{d.field}</td>
                        <td>
                          <pre>{JSON.stringify(d.before, null, 2) ?? 'Desconhecido'}</pre>
                        </td>
                        <td>
                          <pre>{JSON.stringify(d.after, null, 2) ?? 'Desconhecido'}</pre>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </details>
          <div className="gap-grid">
            {[report.before, report.after].map((c, i) => (
              <div key={i}>
                <h3>
                  Contexto {i === 0 ? 'A' : 'B'} · {c.synthetic ? 'Demo sintético' : 'Linux real'}
                </h3>
                <p>
                  {c.cohorts.length} configurações históricas. Fonte conectada não é inferida deste
                  relatório.
                </p>
                {c.cohorts.map((group) => (
                  <details className="scope-details" key={group.context_sha256}>
                    <summary>
                      Testes, versões, ATT&CK, regras e fonte · {group.run_ids.length} execuções
                    </summary>
                    <pre>{JSON.stringify(group, null, 2)}</pre>
                  </details>
                ))}
                <details className="scope-details">
                  <summary>Inspecionar seleção, membros e origem {i === 0 ? 'A' : 'B'}</summary>
                  <pre>{JSON.stringify(c, null, 2)}</pre>
                </details>
              </div>
            ))}
          </div>
          <div className="inline-actions">
            {['pdf', 'html', 'json'].map((format) => (
              <button
                key={format}
                className="button"
                disabled={!ready}
                onClick={() => void exportReport(format)}
              >
                Exportar laboratórios {format.toUpperCase()}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
