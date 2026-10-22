import { useState } from 'react'
import { Failure, Loading, Modal, useData } from './lib'
import type { Page, Rule, RuleVersion, SigmaAnalysis } from './types'

const checks: Record<string, string> = {
  condition_resolution: 'Resolução de condições',
  unused_selection: 'Seleções não referenciadas',
  all_without_contains: 'Uso de all sem contains',
  consecutive_wildcards: 'Curingas consecutivos',
  control_character: 'Caracteres de controle',
}
const severities: Record<string, string> = { HIGH: 'Alta', MEDIUM: 'Média', LOW: 'Baixa' }

export function RuleAnalysis({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const versions = useData<Page<RuleVersion>>(`/rules/${rule.id}/versions`)
  const [selected, setSelected] = useState('')
  const saved = versions.data?.items.find((v) => v.id === selected) ?? versions.data?.items[0]
  return (
    <Modal title={`Análise estática · ${rule.title}`} onClose={onClose}>
      <p className="notice">
        Verificações parciais do conteúdo salvo. Não comprovam eficácia, disponibilidade de
        telemetria ou implantação da regra.
      </p>
      {versions.isLoading ? (
        <Loading />
      ) : versions.error ? (
        <Failure error={versions.error} />
      ) : saved ? (
        <>
          <label>
            Versão para análise
            <select value={saved.id} onChange={(e) => setSelected(e.target.value)}>
              {versions.data!.items.map((v) => (
                <option key={v.id} value={v.id}>
                  v{v.version} · {v.id}
                </option>
              ))}
            </select>
          </label>
          <AnalysisResult key={saved.id} ruleId={rule.id} saved={saved} />
        </>
      ) : (
        <p>Nenhuma versão disponível para análise.</p>
      )}
    </Modal>
  )
}

function AnalysisResult({ ruleId, saved }: { ruleId: string; saved: RuleVersion }) {
  const result = useData<SigmaAnalysis>(`/rules/${ruleId}/versions/${saved.id}/analysis`)
  if (result.isLoading) return <Loading />
  if (result.error) return <Failure error={result.error} />
  const data = result.data
  if (!data) return null
  if (
    data.rule_id !== ruleId ||
    data.rule_version_id !== saved.id ||
    data.rule_version !== saved.version ||
    data.sha256 !== saved.sha256
  )
    return <Failure error={new Error('A análise recebida não corresponde à versão selecionada.')} />
  return (
    <>
      <p className="mono muted-text">
        v{data.rule_version} · {data.rule_version_id}
        <br />
        SHA-256: {data.sha256}
        <br />
        {data.analyzer_version} · pySigma {data.pysigma_version}
      </p>
      <h3>
        {data.findings.length
          ? `${data.findings.length} achado(s) para revisão`
          : 'Nenhum achado nos checks executados'}
      </h3>
      <p className="muted-text">Prioridade de revisão da regra; não representa risco de negócio.</p>
      {data.findings.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Prioridade</th>
                <th>Achado</th>
                <th>Contexto</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((finding, i) => (
                <tr key={i}>
                  <td>{severities[finding.severity] ?? finding.severity}</td>
                  <td>
                    {finding.message}
                    <small className="mono muted-text">
                      {finding.code} · {finding.origin}
                    </small>
                  </td>
                  <td>
                    {finding.selection && <div>Seleção: {finding.selection}</div>}
                    {finding.field && <div>Campo: {finding.field}</div>}
                    {finding.condition_index !== undefined && (
                      <div>Condição: {finding.condition_index + 1}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h3>Fatos do conteúdo</h3>
      <p>Campos declarados: {data.facts.declared_fields.join(', ') || 'Nenhum campo vinculado'}</p>
      <p>Seleções: {data.facts.selections.join(', ')}</p>
      {data.facts.keyword_selections.length > 0 && (
        <p>Seleções de palavras-chave: {data.facts.keyword_selections.join(', ')}</p>
      )}
      <pre>{JSON.stringify(data.facts.logsource, null, 2)}</pre>
      <pre>{data.facts.conditions.join('\n')}</pre>
      <h3>Verificações executadas</h3>
      <ul>
        {data.checks.map((check) => (
          <li key={check}>{checks[check] ?? check}</li>
        ))}
      </ul>
      {data.skipped_checks.length > 0 && (
        <p>
          Não executadas por condição não resolvida:{' '}
          {data.skipped_checks.map((check) => checks[check] ?? check).join(', ')}.
        </p>
      )}
      <h3>Conversão e implantação</h3>
      <p>Backend e pipeline não configurados. Nenhuma conversão ou implantação realizada.</p>
      <ul>
        {data.limitations.map((limit) => (
          <li key={limit}>{limit}</li>
        ))}
      </ul>
    </>
  )
}
