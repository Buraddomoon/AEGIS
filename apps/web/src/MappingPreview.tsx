import { useState } from 'react'
import { Failure, Loading, useData } from './lib'
import type { ConversionProfile, RuleVersion, SigmaMappingPreview } from './types'

type Props = { ruleId: string; saved: RuleVersion; profile: ConversionProfile }

export function MappingPreview(props: Props) {
  const [visible, setVisible] = useState(false)
  return (
    <section>
      <h3>Prévia de transformação de campos</h3>
      <p className="muted-text">
        Aplica uma renomeação revisada em memória. Não gera consulta, não verifica o índice e não
        implanta regras.
      </p>
      <button className="button secondary" onClick={() => setVisible(!visible)}>
        {visible ? 'Ocultar prévia de campos' : 'Gerar prévia de campos'}
      </button>
      {visible && (
        <PreviewResult
          key={`${props.ruleId}:${props.saved.id}:${props.saved.sha256}:${props.profile.sha256}`}
          {...props}
        />
      )}
    </section>
  )
}

function PreviewResult({ ruleId, saved, profile }: Props) {
  const result = useData<SigmaMappingPreview>(
    `/rules/${ruleId}/versions/${saved.id}/mapping-preview?profile_id=${encodeURIComponent(profile.id)}`,
  )
  if (result.isLoading) return <Loading />
  if (result.error) return <Failure error={result.error} />
  const data = result.data
  if (!data) return null
  const digests = [data.pipeline?.sha256, data.document_sha256]
  if (
    data.rule_id !== ruleId ||
    data.rule_version_id !== saved.id ||
    data.rule_version !== saved.version ||
    data.sha256 !== saved.sha256 ||
    data.profile?.id !== profile.id ||
    data.profile?.sha256 !== profile.sha256 ||
    data.preview_version !== 'sigma-mapping-preview/1' ||
    data.pipeline?.version !== data.preview_version ||
    data.pipeline?.profile_id !== profile.id ||
    data.pipeline?.profile_sha256 !== profile.sha256 ||
    digests.some((hash) => !hash || !/^[a-f0-9]{64}$/.test(hash)) ||
    data.can_convert !== false ||
    data.query_generated !== false ||
    data.siem_queried !== false ||
    data.deployment_performed !== false ||
    data.index_mapping_verified !== false ||
    !['previewed', 'unsupported'].includes(data.status) ||
    (data.status === 'previewed' && (!data.before_detection || !data.after_detection)) ||
    (data.status === 'unsupported' && (data.before_detection || data.after_detection))
  )
    return (
      <Failure
        error={
          new Error(
            'A prévia recebida não corresponde à versão, ao perfil ou ao contrato revisado.',
          )
        }
      />
    )
  return (
    <div>
      <h4>
        {data.status === 'previewed'
          ? 'Prévia de campos gerada'
          : 'Regra fora do subconjunto da prévia'}
      </h4>
      {data.blockers.length > 0 && (
        <ul>
          {data.blockers.map((blocker) => (
            <li key={blocker.code}>{blocker.message}</li>
          ))}
        </ul>
      )}
      {data.status === 'previewed' && (
        <>
          <p className="notice">Somente campos transformados. Conversão SIEM continua bloqueada.</p>
          <h4>Antes · detection normalizada</h4>
          <pre>{JSON.stringify(data.before_detection, null, 2)}</pre>
          <h4>Depois · detection normalizada</h4>
          <pre>{JSON.stringify(data.after_detection, null, 2)}</pre>
        </>
      )}
      <details>
        <summary>Integridade e limites da prévia</summary>
        <p className="mono muted-text">
          {data.preview_version} · pySigma {data.pipeline.pysigma_version}
          <br />
          Pipeline SHA-256: {data.pipeline.sha256}
          <br />
          Documento SHA-256: {data.document_sha256}
        </p>
        <ul>
          {data.limitations.map((limit) => (
            <li key={limit}>{limit}</li>
          ))}
        </ul>
      </details>
    </div>
  )
}
