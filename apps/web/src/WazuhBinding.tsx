import { useState } from 'react'
import { api, Badge, Failure, Loading, Modal, useAction, useData } from './lib'
import type { Lab, User } from './types'

export interface WazuhBindingState {
  status: string
  configuration_available: boolean
  proposed_policy: Record<string, unknown> | null
  binding: {
    agent_id: string
    expected_rule: string
    configuration_hash: string
    review: string
  } | null
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
  const data = useData<WazuhBindingState>(`/labs/${lab.id}/wazuh-binding`),
    [review, setReview] = useState(''),
    [confirmed, setConfirmed] = useState(false),
    { busy, run } = useAction()
  const state = data.data,
    editable = !lab.authorized && !lab.active_run_id
  return (
    <Modal title="Coleta Wazuh do laboratório" onClose={onClose}>
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        state && (
          <>
            <Badge value={state.status} />
            <p>{state.limitation}</p>
            <div className="notice">
              O vínculo não executa teste nem consulta o Indexer. Cada campanha precisa de aprovação
              própria. Para revisar/remover, revogue o laboratório e finalize o cleanup.
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
            {state.proposed_policy ? (
              <details className="scope-details" open>
                <summary>Política proposta pela implantação</summary>
                <pre>{JSON.stringify(state.proposed_policy, null, 2)}</pre>
              </details>
            ) : (
              <div className="notice warning">
                Política Wazuh válida para este laboratório não está disponível na implantação.
                Nenhuma conexão ou detecção foi validada.
              </div>
            )}
            {user.role === 'administrator' && (
              <form
                onSubmit={(event) => {
                  event.preventDefault()
                  void run(
                    () =>
                      api(`/labs/${lab.id}/wazuh-binding`, {
                        method: 'PUT',
                        body: JSON.stringify({ review, confirm_read_only_scope: confirmed }),
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
                    disabled={!editable}
                    placeholder="Revise identidade, agent.id, regra, índices e limites; registre a autorização de leitura."
                  />
                </label>
                <label className="checkbox-label">
                  <input
                    required
                    type="checkbox"
                    checked={confirmed}
                    disabled={!editable}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />
                  <span>
                    Revisei o agente, regra, índices e limites. Autorizo somente a coleta de leitura
                    neste escopo quando a campanha for aprovada.
                  </span>
                </label>
                <div className="form-actions">
                  {state.binding && (
                    <button
                      className="button"
                      type="button"
                      disabled={busy || !editable || !confirmed}
                      onClick={() =>
                        void run(
                          () =>
                            api(`/labs/${lab.id}/wazuh-binding/remove`, {
                              method: 'POST',
                              body: JSON.stringify({ confirm: true }),
                            }),
                          'Vínculo removido; histórico preservado.',
                        )
                      }
                    >
                      Remover vínculo
                    </button>
                  )}
                  <button
                    className="button primary"
                    type="submit"
                    disabled={busy || !editable || !confirmed || !state.configuration_available}
                  >
                    Registrar revisão
                  </button>
                </div>
              </form>
            )}
          </>
        )
      )}
    </Modal>
  )
}
