import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Download, ShieldCheck } from 'lucide-react'
import { CoverageFilters, runOptions, useCoverageFilters } from './CoverageFilters'
import { ScopeChanges } from './ScopeChanges'
import {
  api,
  Badge,
  date,
  downloadFile,
  Failure,
  Loading,
  PageHeading,
  Panel,
  useAction,
  useData,
} from './lib'
import type { Comparison, Coverage } from './types'

export function CoveragePage() {
  const filters = useCoverageFilters(),
    data = useData<Coverage>(`/coverage?${filters.query}`, 5000),
    runs = useQuery({
      queryKey: ['coverage-runs', filters.query],
      queryFn: () => runOptions(filters.query),
      retry: 1,
    }),
    [before, setBefore] = useState(''),
    [after, setAfter] = useState(''),
    [comparison, setComparison] = useState<Comparison | null>(null),
    { busy, run } = useAction()
  const reset = () => {
    setBefore('')
    setAfter('')
    setComparison(null)
  }
  const c = data.data,
    mismatch = !!(c?.scope_sha256 && runs.data && runs.data.scope_sha256 !== c.scope_sha256),
    locked =
      busy || filters.dirty || data.isFetching || runs.isFetching || !!runs.error || mismatch,
    exportLocked = busy || filters.dirty || data.isFetching || !c?.scope_sha256
  return (
    <>
      <PageHeading
        eyebrow="OBSERVAR. DETECTAR. MELHORAR."
        title="Cobertura de detecção"
        description="Indicadores por período e release, com denominadores explícitos e histórico preservado."
      />
      <CoverageFilters filters={filters} busy={busy} onChange={reset} onApply={reset} />
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        c && (
          <>
            <div className="stats-grid">
              <div className="metric">
                <span>Técnicas no catálogo de referência</span>
                <strong>{c.catalogued_techniques ?? '—'}</strong>
                <p>
                  {c.selection?.evaluation_catalog
                    ? `Enterprise v${c.selection.evaluation_catalog.version}`
                    : 'Versão não registrada no legado'}
                </p>
              </div>
              <div className="metric">
                <span>Técnicas avaliadas na referência</span>
                <strong>{c.evaluated_techniques ?? '—'}</strong>
                <p>
                  {c.historical_evaluated_techniques ?? c.evaluated_techniques} IDs referenciados
                  nos resultados do recorte
                </p>
              </div>
              <div className="metric metric-accent">
                <span>Detectados / testes válidos · recorte</span>
                <strong>
                  {c.outcomes.DETECTED ?? 0} / {c.valid_tests}
                </strong>
                <p>
                  {c.detected_percentage === null
                    ? 'Sem denominador válido'
                    : `${c.detected_percentage}% neste recorte`}
                </p>
              </div>
              <div className="metric">
                <span>Inconclusivos</span>
                <strong>{c.outcomes.INCONCLUSIVE ?? 0}</strong>
                <p>Excluídos da taxa de detecção</p>
              </div>
            </div>
            <div className="notice">
              <ShieldCheck size={19} />
              <div>
                {c.scope}
                <p>
                  {c.denominator}. {c.limitation}
                </p>
              </div>
            </div>
            <Panel
              title="Escopo e exportação"
              subtitle="O relatório captura um snapshot na exportação; novos dados do mesmo recorte podem ser incluídos."
            >
              <p>
                {c.total_runs} execuções no recorte · {c.completed_tests} testes concluídos ·{' '}
                {c.unversioned_runs ?? 0} execuções sem versão registrada.
              </p>
              <p className="muted-text">
                Snapshot consultado: {c.snapshot_at ? date(c.snapshot_at) : 'não informado'} ·
                início inclusivo/fim exclusivo.
              </p>
              <div className="inline-actions">
                {(['html', 'json'] as const).map((format) => (
                  <button
                    key={format}
                    className="button"
                    disabled={exportLocked}
                    onClick={() =>
                      void run(
                        () =>
                          downloadFile(
                            `/coverage/report?${filters.query}&expected_scope_sha256=${c.scope_sha256}&format=${format}`,
                            `aegis-coverage-${c.scope_sha256?.slice(0, 12)}.${format}`,
                          ),
                        'Recorte exportado.',
                      )
                    }
                  >
                    <Download size={15} />
                    Exportar recorte {format.toUpperCase()}
                  </button>
                ))}
              </div>
              <details className="scope-details">
                <summary>Inspecionar recorte, estados e denominadores</summary>
                <pre>
                  {JSON.stringify(
                    {
                      selection: c.selection,
                      scope_sha256: c.scope_sha256,
                      run_states: c.run_states,
                      denominator: c.denominator,
                    },
                    null,
                    2,
                  )}
                </pre>
              </details>
            </Panel>
          </>
        )
      )}
      <Panel
        title="Comparação entre execuções"
        subtitle="Escolha duas execuções concluídas da mesma campanha dentro do recorte aplicado."
      >
        {runs.error && <Failure error={runs.error} />}
        {mismatch && (
          <div className="notice warning">
            A referência do catálogo mudou entre indicadores e opções. Recarregue o recorte antes de
            comparar.
          </div>
        )}
        {runs.isLoading && <Loading />}
        <form
          className="comparison-form"
          onSubmit={(e) => {
            e.preventDefault()
            void run(async () => {
              const result = await api<Comparison>(
                `/coverage/compare?before=${before}&after=${after}`,
              )
              if (result.before_id !== before || result.after_id !== after)
                throw new Error('Resposta de comparação incompatível com a seleção.')
              setComparison(result)
            }, 'Comparação carregada.')
          }}
        >
          <label>
            Execução anterior
            <select
              required
              disabled={locked}
              value={before}
              onChange={(e) => {
                setBefore(e.target.value)
                setAfter('')
                setComparison(null)
              }}
            >
              <option value="">Selecione uma execução</option>
              {runs.data?.items.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id.slice(0, 8)} · {date(r.created_at)}
                </option>
              ))}
            </select>
          </label>
          <ArrowRight size={20} />
          <label>
            Execução atual
            <select
              required
              disabled={locked}
              value={after}
              onChange={(e) => {
                setAfter(e.target.value)
                setComparison(null)
              }}
            >
              <option value="">Selecione uma execução</option>
              {runs.data?.items
                .filter(
                  (r) =>
                    r.id !== before &&
                    r.campaign_id ===
                      runs.data?.items.find((item) => item.id === before)?.campaign_id,
                )
                .map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.id.slice(0, 8)} · {date(r.created_at)}
                  </option>
                ))}
            </select>
          </label>
          <button
            className="button primary"
            disabled={locked || !before || !after || before === after}
          >
            Comparar execuções
          </button>
        </form>
        {comparison && (
          <>
            <div className={`notice ${comparison.comparable ? '' : 'warning'}`}>
              {comparison.comparable
                ? 'Configurações equivalentes; comparação do mesmo escopo.'
                : 'Equivalência não confirmada. Revise diferenças, contexto desconhecido ou resultados parciais antes de concluir melhoria ou regressão.'}
            </div>
            <div className="inline-actions">
              {(['html', 'json'] as const).map((format) => (
                <button
                  key={format}
                  className="button"
                  disabled={locked}
                  onClick={() =>
                    void run(
                      () =>
                        downloadFile(
                          `/coverage/compare/report?before=${comparison.before_id}&after=${comparison.after_id}&format=${format}`,
                          `aegis-comparison-${comparison.before_id.slice(0, 8)}-${comparison.after_id.slice(0, 8)}.${format}`,
                        ),
                      'Comparação exportada.',
                    )
                  }
                >
                  <Download size={15} />
                  Exportar comparação {format.toUpperCase()}
                </button>
              ))}
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Teste</th>
                    <th>Anterior</th>
                    <th>Atual</th>
                    <th>Mudança</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.tests.map((t) => (
                    <tr key={t.test_id}>
                      <td>{t.test_id}</td>
                      <td>
                        <Badge value={t.before} />
                      </td>
                      <td>
                        <Badge value={t.after} />
                      </td>
                      <td>{t.changed ? 'Resultado alterado' : 'Sem alteração'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mono muted-text comparison-context">
              Execuções: {comparison.before_id} → {comparison.after_id}
            </p>
            <ScopeChanges changes={comparison.scope_changes} />
            <details className="scope-details">
              <summary>Inspecionar configurações, regras e ambiente</summary>
              <pre>
                {JSON.stringify(
                  {
                    antes: comparison.before_scope,
                    depois: comparison.after_scope,
                    comparability_reasons: comparison.comparability_reasons,
                  },
                  null,
                  2,
                )}
              </pre>
            </details>
          </>
        )}
      </Panel>
      {c && !data.error && (
        <Panel
          title="Lacunas observadas"
          subtitle="Somente resultados do recorte aplicado; categorias não comprovam risco de negócio."
        >
          <div className="gap-grid">
            {['OBSERVED_NOT_ALERTED', 'NO_TELEMETRY', 'INCONCLUSIVE'].map((s) => (
              <div key={s}>
                <Badge value={s} />
                <strong>{c.outcomes[s] ?? 0}</strong>
                <p>
                  {s === 'OBSERVED_NOT_ALERTED'
                    ? 'Revisar a regra esperada e repetir após mudanças aprovadas.'
                    : s === 'NO_TELEMETRY'
                      ? 'Verificar instrumentação e disponibilidade da coleta.'
                      : 'Restabelecer a fonte de dados para obter uma conclusão confiável.'}
                </p>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </>
  )
}
