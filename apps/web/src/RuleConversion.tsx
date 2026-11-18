import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, Empty, Failure, Loading, Modal, useData } from './lib'
import type { Page, Rule, RuleVersion } from './types'

export interface QueryContract {
  version: string
  profile: { id: string; name: string; sha256: string; index_mapping_verified: false }
  packages: Record<string, string>
  pipeline: string
  output_format: string
  lock_sha256: string
  implementation_sha256: string
  sha256: string
}
export interface QueryArtifact {
  rule_id: string
  rule_version_id: string
  rule_version: number
  sha256: string
  conversion_version: string
  contract: QueryContract
  status: 'converted' | 'unsupported'
  blockers: { code: string; message: string }[]
  query: string | null
  query_sha256: string | null
  document_sha256: string
  conversion_performed: boolean
  siem_queried: false
  deployment_performed: false
  index_mapping_verified: false
  limitations: string[]
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  const object = value as Record<string, unknown>
  return (
    '{' +
    Object.keys(object)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonical(object[k]))
      .join(',') +
    '}'
  )
}
export async function sha256(text: string) {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))),
  )
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export async function validateArtifact(
  data: QueryArtifact,
  ruleId: string,
  saved: RuleVersion,
  contract: QueryContract,
) {
  const invalid = () =>
    new Error('A consulta recebida não corresponde à versão, ao perfil ou à integridade esperada.')
  if (
    !data ||
    data.rule_id !== ruleId ||
    data.rule_version_id !== saved.id ||
    data.rule_version !== saved.version ||
    data.sha256 !== saved.sha256 ||
    data.conversion_version !== 'sigma-query/1' ||
    data.contract?.sha256 !== contract.sha256 ||
    data.contract.version !== 'sigma-query/1' ||
    data.contract.pipeline !== 'FieldMappingTransformation/1' ||
    data.contract.output_format !== 'default' ||
    data.contract.packages?.pysigma !== '1.5.1' ||
    data.contract.packages?.['pysigma-backend-opensearch'] !== '2.0.3' ||
    data.contract.packages?.['pysigma-backend-elasticsearch'] !== '2.1.1' ||
    Object.keys(data.contract.packages).length !== 3 ||
    data.contract?.profile?.id !== 'aegis-marker-lucene/1' ||
    data.contract.profile.sha256 !== contract.profile.sha256 ||
    data.contract.profile.index_mapping_verified !== false ||
    data.siem_queried !== false ||
    data.deployment_performed !== false ||
    data.index_mapping_verified !== false ||
    !Array.isArray(data.blockers) ||
    !data.blockers.every((b) => typeof b?.code === 'string' && typeof b?.message === 'string') ||
    !Array.isArray(data.limitations) ||
    !data.limitations.every((l) => typeof l === 'string') ||
    !['converted', 'unsupported'].includes(data.status)
  )
    throw invalid()
  const { sha256: contractHash, ...contractBody } = data.contract
  const { document_sha256: documentHash, ...documentBody } = data
  if (
    (await sha256(canonical(contractBody))) !== contractHash ||
    (await sha256(canonical(documentBody))) !== documentHash
  )
    throw invalid()
  if (data.status === 'converted') {
    if (
      !data.conversion_performed ||
      data.blockers.length ||
      typeof data.query !== 'string' ||
      !data.query ||
      new TextEncoder().encode(data.query).length > 8192 ||
      /[\x00-\x1f\x7f]/.test(data.query) ||
      (await sha256(data.query)) !== data.query_sha256
    )
      throw invalid()
  } else if (
    data.query !== null ||
    data.query_sha256 !== null ||
    data.conversion_performed ||
    !data.blockers.length
  )
    throw invalid()
  return data
}

export function RuleConversion({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const versions = useData<Page<RuleVersion>>(`/rules/${rule.id}/versions`)
  const profiles = useData<{ items: QueryContract[]; configured: boolean }>('/sigma/query-profiles')
  const [versionId, setVersionId] = useState('')
  const [requested, setRequested] = useState(false)
  const saved = versions.data?.items.find((v) => v.id === versionId) ?? versions.data?.items[0]
  const contract = profiles.data?.items[0]
  return (
    <Modal title={`Consulta Sigma · ${rule.title}`} onClose={onClose}>
      <p className="notice">
        Gera uma consulta offline para revisão. Não consulta o SIEM, não implanta regras e não
        comprova eficácia.
      </p>
      {versions.isLoading || profiles.isLoading ? (
        <Loading />
      ) : versions.error || profiles.error ? (
        <Failure error={(versions.error ?? profiles.error)!} />
      ) : !saved || !contract ? (
        <Empty title="Conversão indisponível" />
      ) : (
        <>
          <label>
            Versão da regra
            <select
              value={saved.id}
              onChange={(e) => {
                setVersionId(e.target.value)
                setRequested(false)
              }}
            >
              {versions.data!.items.map((v) => (
                <option key={v.id} value={v.id}>
                  v{v.version} · {v.id}
                </option>
              ))}
            </select>
          </label>
          <p>
            {contract.profile.name} · {contract.profile.id}
          </p>
          {!profiles.data!.configured ? (
            <p role="status">Conversor não configurado nesta instalação.</p>
          ) : (
            <>
              <button className="button secondary" onClick={() => setRequested(!requested)}>
                {requested ? 'Ocultar consulta' : 'Gerar consulta offline'}
              </button>
              {requested && (
                <ConversionResult
                  key={`${rule.id}:${saved.id}:${saved.sha256}:${contract.sha256}`}
                  ruleId={rule.id}
                  saved={saved}
                  contract={contract}
                />
              )}
            </>
          )}
        </>
      )}
    </Modal>
  )
}

export function ConversionResult({
  ruleId,
  saved,
  contract,
}: {
  ruleId: string
  saved: RuleVersion
  contract: QueryContract
}) {
  const path = `/rules/${ruleId}/versions/${saved.id}/query?profile_id=${encodeURIComponent(contract.profile.id)}`
  const result = useQuery({
    queryKey: [path, saved.sha256, contract.sha256, contract.profile.sha256],
    queryFn: async () => validateArtifact(await api<QueryArtifact>(path), ruleId, saved, contract),
    retry: false,
  })
  if (result.isFetching) return <Loading />
  if (result.error) return <Failure error={result.error} />
  const data = result.data
  if (!data) return null
  function download() {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `sigma-query-v${saved.version}-${data!.document_sha256}.json`
    anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <section>
      <h3>
        {data.status === 'converted'
          ? 'Consulta gerada para revisão'
          : 'Conversão não suportada para esta versão'}
      </h3>
      {data.status === 'converted' ? (
        <>
          <pre>{data.query}</pre>
          <button className="button secondary" onClick={download}>
            Baixar consulta e procedência
          </button>
        </>
      ) : (
        <ul>
          {data.blockers.map((b) => (
            <li key={b.code}>{b.message}</li>
          ))}
        </ul>
      )}
      <p className="mono muted-text">
        Regra {data.rule_id} · v{data.rule_version} · {data.rule_version_id}
        <br />
        SHA-256: {data.sha256}
      </p>
      <details>
        <summary>Procedência e limites da consulta</summary>
        <p className="mono muted-text">
          {data.conversion_version} · {data.contract.profile.id}
          <br />
          Perfil SHA-256: {data.contract.profile.sha256}
          <br />
          Contrato SHA-256: {data.contract.sha256}
          <br />
          Lock SHA-256: {data.contract.lock_sha256}
          <br />
          Implementação SHA-256: {data.contract.implementation_sha256}
          <br />
          Consulta SHA-256: {data.query_sha256 ?? 'Não gerada'}
          <br />
          Documento SHA-256: {data.document_sha256}
        </p>
        <p>
          Backend/pacotes:{' '}
          {Object.entries(data.contract.packages)
            .map(([name, version]) => `${name} ${version}`)
            .join(' · ')}
          . Pipeline: {data.contract.pipeline}.
        </p>
        <ul>
          {data.limitations.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      </details>
    </section>
  )
}
