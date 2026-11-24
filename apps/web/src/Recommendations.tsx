import { useEffect, useRef, useState } from 'react'
import { downloadFile, Panel } from './lib'
import type { EventRecord, RunDetail } from './types'

export interface RecommendationAnalysis {
  kind: string
  run_id: string
  synthetic: boolean
  policy: { version: string }
  policy_sha256: string
  input_sha256: string
  integrity_sha256: string
  limitations: string[]
  items: {
    execution_id: string | null
    execution_index: number
    test_id: string
    code: string
    priority: number
    reason: string
    action: string
    facts: Record<string, unknown>
    evidence: {
      event_id: string | null
      source: string | null
      sha256: string | null
      event_present: boolean
    }[]
  }[]
}

export function matchingAnalysis(analysis: RecommendationAnalysis, run: RunDetail) {
  const hash = /^[a-f0-9]{64}$/
  return (
    analysis?.kind === 'new_analysis' &&
    analysis.run_id === run.id &&
    analysis.synthetic === run.synthetic &&
    analysis.policy?.version === 'aegis-recommendations/1' &&
    [analysis.policy_sha256, analysis.input_sha256, analysis.integrity_sha256].every((v) =>
      hash.test(v),
    ) &&
    Array.isArray(analysis.limitations) &&
    analysis.limitations.every((value) => typeof value === 'string') &&
    Array.isArray(analysis.items) &&
    analysis.items.every(
      (item) =>
        item &&
        typeof item.reason === 'string' &&
        typeof item.action === 'string' &&
        typeof item.test_id === 'string' &&
        typeof item.code === 'string' &&
        Number.isInteger(item.execution_index) &&
        Number.isFinite(item.priority) &&
        item.facts &&
        typeof item.facts === 'object' &&
        !Array.isArray(item.facts) &&
        Array.isArray(item.evidence) &&
        item.evidence.every(
          (e) =>
            e &&
            (e.event_id === null || typeof e.event_id === 'string') &&
            (e.source === null || typeof e.source === 'string') &&
            (e.sha256 === null || hash.test(e.sha256)) &&
            typeof e.event_present === 'boolean',
        ) &&
        run.executions[item.execution_index]?.id === item.execution_id,
    )
  )
}

export function Recommendations({
  run,
  onEvent,
  onRefresh,
}: {
  run: RunDetail
  onEvent: (event: EventRecord) => void
  onRefresh: () => Promise<unknown>
}) {
  const analysis = run.recommendation_analysis
  if (!analysis || !matchingAnalysis(analysis, run))
    return (
      <Panel title="Recomendações">
        <p>Análise indisponível ou incompatível; reconsulte a execução.</p>
      </Panel>
    )
  return (
    <Analysis
      key={analysis.integrity_sha256}
      analysis={analysis}
      run={run}
      onEvent={onEvent}
      onRefresh={onRefresh}
    />
  )
}

function Analysis({
  analysis,
  run,
  onEvent,
  onRefresh,
}: {
  analysis: RecommendationAnalysis
  run: RunDetail
  onEvent: (event: EventRecord) => void
  onRefresh: () => Promise<unknown>
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    pending = useRef<AbortController | null>(null)
  useEffect(() => () => pending.current?.abort(), [])
  async function exportAnalysis(format: 'json' | 'html' | 'pdf') {
    const controller = new AbortController()
    pending.current = controller
    setBusy(true)
    try {
      const params = new URLSearchParams({
        format,
        expected_analysis_sha256: analysis.integrity_sha256,
      })
      await downloadFile(
        `/reports/${encodeURIComponent(run.id)}/recommendations?${params}`,
        `aegis-recommendations-${run.id}.${format}`,
        controller.signal,
      )
    } catch (failure) {
      if (!controller.signal.aborted)
        setError(
          failure instanceof Error ? failure.message : 'Falha ao exportar; reconsulte a execução.',
        )
    } finally {
      if (!controller.signal.aborted) setBusy(false)
    }
  }
  return (
    <Panel
      title="Recomendações por evidência"
      subtitle="Análise nova separada. Ordem técnica de investigação; não é classificação de risco."
    >
      <p>
        {run.synthetic ? 'Dados sintéticos' : 'Registros de laboratório real'} · Política{' '}
        {analysis.policy.version}
      </p>
      <details className="scope-details">
        <summary>Política, integridade e limites da análise</summary>
        <p className="mono">Política SHA256: {analysis.policy_sha256}</p>
        <p className="mono">Entrada SHA256: {analysis.input_sha256}</p>
        <p className="mono">Análise SHA256: {analysis.integrity_sha256}</p>
        <ul>
          {analysis.limitations.map((text, i) => (
            <li key={i}>{text}</li>
          ))}
        </ul>
      </details>
      {error && <p role="alert">{error}</p>}
      <div className="execution-toolbar">
        {(['json', 'html', 'pdf'] as const).map((format) => (
          <button
            key={format}
            className="button"
            disabled={busy || !!error}
            onClick={() => void exportAnalysis(format)}
          >
            Exportar recomendações {format.toUpperCase()}
          </button>
        ))}
        {error && (
          <button
            className="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true)
              try {
                await onRefresh()
                setError('')
              } catch {
                setError('Falha ao reconsultar; tente novamente.')
              } finally {
                setBusy(false)
              }
            }}
          >
            Reconsultar execução
          </button>
        )}
      </div>
      {analysis.items.length === 0 && <p>Nenhum teste registrado para analisar.</p>}
      <div className="execution-results">
        {analysis.items.map((item) => (
          <article className="result-card" key={`${item.execution_index}:${item.code}`}>
            <strong>
              {item.test_id} · ordem técnica {item.priority}
            </strong>
            <p>{item.reason}</p>
            <p>{item.action}</p>
            <details className="scope-details">
              <summary>Fatos registrados · {item.code}</summary>
              <pre>{JSON.stringify(item.facts, null, 2)}</pre>
            </details>
            {item.evidence.length === 0 && (
              <p>Sem vínculo de evidência defensiva registrado para esta recomendação.</p>
            )}
            {item.evidence.map((evidence, i) => {
              const event = run.executions[item.execution_index]?.events.find(
                (event) => event.id === evidence.event_id && event.sha256 === evidence.sha256,
              )
              return (
                <div key={`${evidence.event_id}:${i}`}>
                  {event && evidence.event_present ? (
                    <button
                      className="button recommendation-evidence"
                      onClick={() => onEvent(event)}
                    >
                      Inspecionar evidência {evidence.event_id}
                    </button>
                  ) : (
                    <p>Evento vinculado indisponível: {evidence.event_id ?? 'ID desconhecido'}</p>
                  )}
                  <p className="mono">
                    Fonte: {evidence.source ?? 'desconhecida'} · SHA256:{' '}
                    {evidence.sha256 ?? 'desconhecido'}
                  </p>
                </div>
              )
            })}
          </article>
        ))}
      </div>
    </Panel>
  )
}
