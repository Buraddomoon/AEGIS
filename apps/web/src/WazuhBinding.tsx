import { useState } from 'react'
import { api, Badge, date, Failure, Loading, Modal, useAction, useData } from './lib'
import type { Lab, User } from './types'

interface Profile {
  id: string
  revision: number
  available: boolean
  configuration_hash: string | null
  policy: Record<string, unknown> | null
}
export interface WazuhBindingState {
  status: string
  configuration_available: boolean
  configuration_hash?: string | null
  profiles_enabled?: boolean
  profiles?: Profile[]
  proposed_policy: Record<string, unknown> | null
  binding: {
    agent_id: string
    expected_rule: string
    configuration_hash: string
    review: string
  } | null
  limitation: string
}
interface Diagnostic {
  status: 'reachable' | 'unavailable' | 'stale'
  configuration_hash: string
  checked_at: string
  events_queried: false
  limitation: string
}

export function WazuhBinding({
  lab,
  user,
  onClose,
}: {
  lab: Lab
  user: User
  onClose: () => void
}) {
  const data = useData<WazuhBindingState>(`/labs/${lab.id}/wazuh-binding`)
  return (
    <Modal title="Coleta Wazuh do laboratório" onClose={onClose}>
      {data.isFetching ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : data.data ? (
        <Configuration
          key={`${lab.id}:${data.dataUpdatedAt}`}
          lab={lab}
          user={user}
          state={data.data}
        />
      ) : null}
    </Modal>
  )
}

function Configuration({ lab, user, state }: { lab: Lab; user: User; state: WazuhBindingState }) {
  const [selected, setSelected] = useState(
    state.profiles?.find((p) => p.configuration_hash === state.binding?.configuration_hash)?.id ??
      '',
  )
  const profile = state.profiles?.find((p) => p.id === selected)
  const policy = state.profiles_enabled ? profile?.policy : state.proposed_policy
  const hash = state.profiles_enabled ? profile?.configuration_hash : state.configuration_hash
  const available = state.profiles_enabled ? !!profile?.available : state.configuration_available
  return (
    <>
      <Badge value={state.status} />
      <p>{state.limitation}</p>
      <div className="notice">
        Revisar não consulta o Indexer. O diagnóstico é pontual e não busca eventos. Para revisar,
        testar ou remover, revogue o laboratório e finalize o cleanup.
      </div>
      {state.binding && (
        <dl>
          <dt>Agente / regra esperada</dt>
          <dd>
            {state.binding.agent_id} / {state.binding.expected_rule}
          </dd>
          <dt>SHA-256 da configuração revisada</dt>
          <dd className="mono">{state.binding.configuration_hash}</dd>
          <dt>Revisão registrada</dt>
          <dd>{state.binding.review}</dd>
        </dl>
      )}
      {state.profiles_enabled && (
        <label>
          Perfil defensivo conhecido
          <select value={selected} onChange={(event) => setSelected(event.target.value)}>
            <option value="">Selecione um perfil para revisar</option>
            {state.profiles?.map((p) => (
              <option key={p.id} value={p.id} disabled={!p.available}>
                {p.id} · revisão {p.revision}
                {p.available ? '' : ' · indisponível'}
              </option>
            ))}
          </select>
        </label>
      )}
      {policy ? (
        <details className="scope-details" open>
          <summary>Política proposta pela implantação</summary>
          {hash && <p className="mono">SHA-256: {hash}</p>}
          <pre>{JSON.stringify(policy, null, 2)}</pre>
        </details>
      ) : (
        <div className="notice warning">
          Política Wazuh válida para este laboratório não está disponível na implantação. Selecione
          um perfil disponível quando houver. Nenhuma conexão ou detecção foi validada.
        </div>
      )}
      {user.role === 'administrator' && (
        <ReviewActions
          key={`${selected}:${hash}`}
          lab={lab}
          state={state}
          profile={profile}
          hash={hash}
          available={available}
        />
      )}
    </>
  )
}

function ReviewActions({
  lab,
  state,
  profile,
  hash,
  available,
}: {
  lab: Lab
  state: WazuhBindingState
  profile?: Profile
  hash?: string | null
  available: boolean
}) {
  const [review, setReview] = useState(''),
    [confirmed, setConfirmed] = useState(false)
  const [diagnostic, setDiagnostic] = useState<Diagnostic | null>(null)
  const { busy: mutating, run } = useAction()
  const [testing, setTesting] = useState(false),
    [testError, setTestError] = useState<Error | null>(null)
  const busy = mutating || testing
  const editable = !lab.authorized && !lab.active_run_id
  const base = `/labs/${lab.id}/wazuh-binding`
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        setConfirmed(false)
        setDiagnostic(null)
        void run(
          () =>
            api(base, {
              method: 'PUT',
              body: JSON.stringify({
                review,
                confirm_read_only_scope: confirmed,
                ...(profile
                  ? { profile_id: profile.id, confirm_configuration_hash: hash }
                  : hash
                    ? { confirm_configuration_hash: hash }
                    : {}),
              }),
            }),
          'Binding revisado; versão do ambiente alterada. Renove o preflight antes de autorizar.',
        )
      }}
    >
      <label>
        Revisão do mapeamento e escopo
        <textarea
          required
          minLength={20}
          maxLength={4000}
          value={review}
          onChange={(e) => setReview(e.target.value)}
          disabled={!editable || busy}
          placeholder="Revise identidade, agente, regra, índices e limites; não inclua credenciais."
        />
      </label>
      <label className="checkbox-label">
        <input
          required
          type="checkbox"
          checked={confirmed}
          disabled={!editable || busy}
          onChange={(e) => setConfirmed(e.target.checked)}
        />
        <span>
          Revisei o agente, regra, índices e limites. Autorizo somente a coleta de leitura neste
          escopo quando a campanha for aprovada.
        </span>
      </label>
      <div className="form-actions wazuh-actions">
        {state.binding && (
          <>
            <button
              className="button"
              type="button"
              disabled={busy || !editable || !confirmed}
              onClick={() => {
                setConfirmed(false)
                setDiagnostic(null)
                void run(
                  () =>
                    api(base + '/remove', {
                      method: 'POST',
                      body: JSON.stringify({
                        confirm: true,
                        confirm_configuration_hash: state.binding!.configuration_hash,
                      }),
                    }),
                  'Vínculo removido; histórico preservado.',
                )
              }}
            >
              Remover vínculo
            </button>
            <button
              className="button"
              type="button"
              disabled={busy || !editable || !confirmed || state.status !== 'reviewed_unverified'}
              onClick={() => {
                setConfirmed(false)
                setDiagnostic(null)
                setTesting(true)
                setTestError(null)
                void (async () => {
                  try {
                    const result = await api<Diagnostic>(base + '/test', {
                      method: 'POST',
                      body: JSON.stringify({
                        confirm: true,
                        confirm_configuration_hash: state.binding!.configuration_hash,
                      }),
                    })
                    if (
                      result.configuration_hash !== state.binding!.configuration_hash ||
                      result.events_queried !== false
                    )
                      throw new Error('Diagnóstico divergente; recarregue a revisão.')
                    setDiagnostic(result)
                  } catch (error) {
                    setTestError(
                      error instanceof Error ? error : new Error('Diagnóstico indisponível.'),
                    )
                  } finally {
                    setTesting(false)
                  }
                })()
              }}
            >
              Testar conexão revisada
            </button>
          </>
        )}
        <button
          className="button primary"
          type="submit"
          disabled={busy || !editable || !confirmed || !available}
        >
          Registrar revisão
        </button>
      </div>
      {testError && <Failure error={testError} />}
      {diagnostic && (
        <div className="notice" role="status">
          <div>
            <p>
              {diagnostic.status === 'reachable'
                ? 'Transporte respondeu ao diagnóstico pontual.'
                : diagnostic.status === 'stale'
                  ? 'Revisão alterada; resultado descartado.'
                  : 'Conector indisponível; quantidade de eventos desconhecida.'}
            </p>
            <p>{diagnostic.limitation}</p>
            <p>{date(diagnostic.checked_at)}</p>
          </div>
        </div>
      )}
    </form>
  )
}
