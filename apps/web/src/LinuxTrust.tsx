import { date } from './lib'
import type { Lab } from './types'

export function LinuxTrust({ lab }: { lab: Lab }) {
  const trust = lab.trust
  const validHash = (value: unknown): value is string =>
    typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
  const matched =
    trust?.matches_deployment === true &&
    validHash(trust.configuration_hash) &&
    trust.configuration_hash === trust.deployment_configuration_hash
  return (
    <div className="notice linux-trust-notice" role="status" aria-label="Confiança Linux">
      <div>
        <strong>
          {matched ? 'Vínculo corresponde à confiança atual' : 'Confiança exige revisão do vínculo'}
        </strong>
        {validHash(trust?.configuration_hash) && (
          <p>
            Vínculo revisado: <code>{trust.configuration_hash}</code>
          </p>
        )}
        {validHash(trust?.deployment_configuration_hash) && (
          <p>
            Implantação atual: <code>{trust.deployment_configuration_hash}</code>
          </p>
        )}
        {trust?.reviewed_at && (
          <p>
            Revisão registrada em {date(trust.reviewed_at)} · ambiente v{lab.environment_version}
          </p>
        )}
        <p>Preflight vigente e autorização do laboratório são verificados separadamente.</p>
      </div>
    </div>
  )
}
