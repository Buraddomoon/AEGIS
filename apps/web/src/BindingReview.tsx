import type { Lab } from './types'
import { date, Failure, Loading, Modal, useData } from './lib'

export interface BindingReviewState {
  format: 'aegis-linux-binding-review/1'
  laboratory_id: string
  environment_version: number
  reviewed_at: string
  status: 'blocked' | 'persisted_prerequisites_satisfied'
  blockers: string[]
  nonterminal_runs: number
  nonterminal_tests: number
  dispatches_examined: number
  dispatch_history_complete: boolean
  unconfirmed_cleanup_count: number
  unconfirmed_execution_ids: string[]
  unconfirmed_sample_truncated: boolean
  runner_contacted: false
  journal_verified: false
  activation_permitted: false
  normal_operation_permitted: false
}

const reasons: Record<string, string> = {
  not_linux: 'Este laboratório não é Linux.',
  laboratory_authorized: 'Revogue a autorização antes de revisar o vínculo.',
  laboratory_reserved: 'Há uma reserva ativa. Preserve o job original até confirmar seu cleanup.',
  nonterminal_runs: 'Há solicitações ou execuções que ainda não terminaram.',
  nonterminal_tests: 'Há testes pendentes, inclusive filhos de execuções encerradas.',
  dispatch_history_limit: 'O histórico excede o limite de revisão; a consulta está incompleta.',
  unconfirmed_cleanup: 'Há dispatches sem confirmação íntegra de cleanup do job original.',
}

function matches(state: BindingReviewState, lab: Lab): boolean {
  return (
    state.format === 'aegis-linux-binding-review/1' &&
    state.laboratory_id === lab.id &&
    state.environment_version === lab.environment_version &&
    typeof state.reviewed_at === 'string' &&
    Number.isFinite(Date.parse(state.reviewed_at)) &&
    Array.isArray(state.blockers) &&
    state.blockers.every((item) => typeof item === 'string') &&
    Array.isArray(state.unconfirmed_execution_ids) &&
    state.unconfirmed_execution_ids.length <= 25 &&
    state.unconfirmed_execution_ids.every((item) => typeof item === 'string') &&
    [
      state.nonterminal_runs,
      state.nonterminal_tests,
      state.dispatches_examined,
      state.unconfirmed_cleanup_count,
    ].every((count) => Number.isSafeInteger(count) && count >= 0) &&
    state.dispatches_examined <= 1000 &&
    typeof state.dispatch_history_complete === 'boolean' &&
    typeof state.unconfirmed_sample_truncated === 'boolean' &&
    state.runner_contacted === false &&
    state.journal_verified === false &&
    state.activation_permitted === false &&
    state.normal_operation_permitted === false &&
    (state.status === 'blocked'
      ? state.blockers.length > 0
      : state.status === 'persisted_prerequisites_satisfied' &&
        state.blockers.length === 0 &&
        state.dispatch_history_complete &&
        state.nonterminal_runs === 0 &&
        state.nonterminal_tests === 0 &&
        state.unconfirmed_cleanup_count === 0 &&
        state.unconfirmed_execution_ids.length === 0 &&
        !state.unconfirmed_sample_truncated)
  )
}

export function BindingReview({ lab, onClose }: { lab: Lab; onClose: () => void }) {
  const data = useData<BindingReviewState>(`/labs/${lab.id}/binding-review`)
  const state = data.data
  return (
    <Modal title="Pendências do vínculo Linux" onClose={onClose}>
      <p>
        Revisão do histórico de {lab.name}. O runner e o SIEM não são consultados. Esta consulta não
        verifica o diário, troca certificados ou autoriza uma execução.
      </p>
      <button className="button" disabled={data.isFetching} onClick={() => void data.refetch()}>
        Atualizar revisão
      </button>
      {data.isFetching ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : state && !matches(state, lab) ? (
        <Failure
          error={
            new Error(
              'Revisão incompatível com o laboratório ou versão do ambiente. Atualize os dados.',
            )
          }
        />
      ) : state ? (
        <>
          <div className={`notice${state.status === 'blocked' ? ' warning' : ''}`} role="status">
            {state.status === 'blocked'
              ? 'Revisão do vínculo bloqueada.'
              : 'Pré-requisitos persistidos atendidos. A ativação continua sem autorização.'}
          </div>
          <dl>
            <dt>Versão do ambiente / consulta</dt>
            <dd>
              v{state.environment_version} · {date(state.reviewed_at)}
            </dd>
            <dt>Solicitações ou execuções pendentes / testes pendentes</dt>
            <dd>
              {state.nonterminal_runs} / {state.nonterminal_tests}
            </dd>
            <dt>Dispatches examinados / cleanup não confirmado entre os examinados</dt>
            <dd>
              {state.dispatches_examined} / {state.unconfirmed_cleanup_count}
            </dd>
            <dt>Histórico de dispatches</dt>
            <dd>
              {state.dispatch_history_complete
                ? 'Completo nesta consulta'
                : 'Incompleto; nenhuma liberação permitida'}
            </dd>
          </dl>
          {state.blockers.length > 0 && (
            <ul>
              {state.blockers.map((reason) => (
                <li key={reason}>
                  {reasons[reason] ?? 'Bloqueio desconhecido: revisão manual necessária.'}
                </li>
              ))}
            </ul>
          )}
          {state.unconfirmed_execution_ids.length > 0 && (
            <details>
              <summary>Identificadores dos testes sem cleanup confirmado</summary>
              <ul className="mono">
                {state.unconfirmed_execution_ids.map((id) => (
                  <li key={id}>{id}</li>
                ))}
              </ul>
              {state.unconfirmed_sample_truncated && (
                <p>Amostra limitada a25 testes; existem outras pendências.</p>
              )}
            </details>
          )}
          <p>
            Cancele solicitações pendentes em{' '}
            <a className="text-link" href="#executions">
              Execuções
            </a>
            . Cleanup exige confirmação do job original. Preserve reservas, identidades e diário; a
            troca de certificados exige revisão própria.
          </p>
        </>
      ) : null}
    </Modal>
  )
}
