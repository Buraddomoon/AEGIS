import { useState } from 'react'
import { Empty, Failure, Loading, Modal, useData } from './lib'
import type {
  ConversionProfile,
  ConversionProfiles,
  ConversionReadiness,
  Page,
  Rule,
  RuleVersion,
} from './types'

export function RuleReadiness({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const versions = useData<Page<RuleVersion>>(`/rules/${rule.id}/versions`)
  const profiles = useData<ConversionProfiles>('/sigma/conversion-profiles')
  const [versionId, setVersionId] = useState(''),
    [profileId, setProfileId] = useState('')
  const saved = versions.data?.items.find((v) => v.id === versionId) ?? versions.data?.items[0]
  const profile = profiles.data?.items.find((p) => p.id === profileId) ?? profiles.data?.items[0]
  const error = versions.error ?? profiles.error
  return (
    <Modal title={`Preparação Sigma · ${rule.title}`} onClose={onClose}>
      <p className="notice">
        Diagnóstico offline de campos e requisitos. Conversão e implantação indisponíveis.
      </p>
      {versions.isLoading || profiles.isLoading ? (
        <Loading />
      ) : error ? (
        <Failure error={error} />
      ) : !saved || !profile ? (
        <Empty title="Preparação indisponível">
          É necessária uma versão salva e um perfil revisado.
        </Empty>
      ) : (
        <>
          <label>
            Versão para preparação
            <select value={saved.id} onChange={(e) => setVersionId(e.target.value)}>
              {versions.data!.items.map((v) => (
                <option key={v.id} value={v.id}>
                  v{v.version} · {v.id}
                </option>
              ))}
            </select>
          </label>
          <label>
            Perfil candidato
            <select value={profile.id} onChange={(e) => setProfileId(e.target.value)}>
              {profiles.data!.items.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} · {p.id}
                </option>
              ))}
            </select>
          </label>
          <ReadinessResult
            key={`${saved.id}:${profile.sha256}`}
            ruleId={rule.id}
            saved={saved}
            profile={profile}
          />
        </>
      )}
    </Modal>
  )
}

function ReadinessResult({
  ruleId,
  saved,
  profile,
}: {
  ruleId: string
  saved: RuleVersion
  profile: ConversionProfile
}) {
  const result = useData<ConversionReadiness>(
    `/rules/${ruleId}/versions/${saved.id}/conversion-readiness?profile_id=${encodeURIComponent(profile.id)}`,
  )
  if (result.isLoading) return <Loading />
  if (result.error) return <Failure error={result.error} />
  const data = result.data
  if (!data) return null
  if (
    data.rule_id !== ruleId ||
    data.rule_version_id !== saved.id ||
    data.rule_version !== saved.version ||
    data.sha256 !== saved.sha256 ||
    data.profile.id !== profile.id ||
    data.profile.sha256 !== profile.sha256
  )
    return (
      <Failure
        error={
          new Error('O diagnóstico recebido não corresponde à versão e ao perfil selecionados.')
        }
      />
    )
  return (
    <>
      <p className="mono muted-text">
        v{data.rule_version} · {data.rule_version_id}
        <br />
        SHA-256: {data.sha256}
        <br />
        {data.readiness_version} · pySigma {data.pysigma_version}
      </p>
      <h3>Conversão bloqueada</h3>
      <ul className="readiness-blockers">
        {data.blockers.map((b, i) => (
          <li key={i}>
            {b.message}
            <small className="mono muted-text">{b.code}</small>
          </li>
        ))}
      </ul>
      <h3>Mapeamento candidato de campos</h3>
      <p>
        Logsource corresponde: {data.logsource_matches ? 'Sim' : 'Não'} · Campos declarados
        mapeados: {data.field_mapping_complete ? 'Sim' : 'Não'}.
      </p>
      <p className="muted-text">
        Nomes mapeados não comprovam equivalência da condição nem mapping físico do índice.
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Campo Sigma declarado</th>
              <th>Caminho candidato</th>
            </tr>
          </thead>
          <tbody>
            {data.mappings.map((row) => (
              <tr key={row.source_field}>
                <td className="mono">{row.source_field}</td>
                <td className="mono">{row.target_field ?? 'Sem mapeamento'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.keyword_selections.length > 0 && (
        <p>Palavras-chave sem destino: {data.keyword_selections.join(', ')}</p>
      )}
      {data.field_references.length > 0 && (
        <p>Referências fieldref sem tratamento: {data.field_references.join(', ')}</p>
      )}
      <details>
        <summary>Metadados e proveniência</summary>
        <p>
          Snapshot de pacotes revisado em {data.backend.snapshot_reviewed_at}. Este diagnóstico usa
          versões instaladas; não consulta PyPI ou SIEM.
        </p>
        <p className="mono muted-text">
          SHA-256 do snapshot: {data.backend.snapshot_sha256}
          <br />
          Perfil: {data.profile.id} · {data.profile.sha256}
        </p>
        {data.backend.packages.map((pkg) => (
          <div key={pkg.name}>
            <h4>
              {pkg.name} · revisada {pkg.version}
            </h4>
            <p>
              Instalada: {pkg.installed ?? 'Ausente'} · Licença do pacote: {pkg.license}.
            </p>
            <ul>
              {pkg.requirements.map((r, i) => (
                <li key={i}>
                  {r.name} {r.required}: instalada {r.installed ?? 'ausente'} ·{' '}
                  {r.satisfied ? 'Requisito atendido' : 'Requisito não atendido'}
                </li>
              ))}
            </ul>
            <a className="text-link" href={pkg.source} target="_blank" rel="noreferrer">
              Metadados oficiais da versão revisada
            </a>
          </div>
        ))}
      </details>
      <h3>Limites da preparação</h3>
      <ul>
        {data.limitations.map((limit) => (
          <li key={limit}>{limit}</li>
        ))}
      </ul>
    </>
  )
}
