import { useState } from 'react'
import { api, date, Empty, Failure, Loading, Modal, useAction, useData } from './lib'
import type { Page, Rule, RuleTestLink, RuleVersion, Test, User } from './types'

export function RuleTestLinks({
  rule,
  user,
  onClose,
}: {
  rule: Rule
  user: User
  onClose: () => void
}) {
  const [history, setHistory] = useState(false),
    [page, setPage] = useState(0),
    [testId, setTestId] = useState(''),
    [rationale, setRationale] = useState(''),
    [confirmedScope, setConfirmedScope] = useState<string | null>(null),
    [retiring, setRetiring] = useState<string | null>(null),
    data = useData<Page<RuleTestLink>>(
      `/rule-test-links?rule_id=${rule.id}&include_retired=${history}&limit=10&offset=${page * 10}`,
    ),
    tests = useData<Page<Test>>('/tests'),
    versions = useData<Page<RuleVersion>>(`/rules/${rule.id}/versions`),
    active = useData<Page<RuleTestLink>>(
      `/rule-test-links?rule_id=${rule.id}&test_id=${encodeURIComponent(testId)}`,
    ),
    { busy, run } = useAction()
  const newest = versions.data?.items[0],
    test = tests.data?.items.find((t) => t.id === testId),
    current = active.data?.items.find((x) => x.test_id === testId),
    error = data.error ?? tests.error ?? versions.error ?? active.error,
    canEdit = user.role !== 'viewer'
  const payload = {
      rule_version_id: newest?.id,
      test_id: test?.id,
      confirm_rule_sha256: newest?.sha256,
      confirm_test_version: test?.version,
      rationale,
      replaces_id: current?.id ?? null,
    },
    fingerprint = JSON.stringify(payload),
    confirmed = confirmedScope !== null && confirmedScope === fingerprint,
    refreshing = versions.isFetching || tests.isFetching || active.isFetching
  return (
    <Modal title={`Testes e revisões · ${rule.title}`} onClose={onClose}>
      <div className="notice warning">
        Vínculo de planejamento. Não implanta a regra, não confirma compatibilidade com o SIEM e não
        comprova detecção. Alterar vínculos exige nova solicitação/aprovação dos escopos afetados.
      </div>
      <div className="toolbar">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={history}
            onChange={(e) => {
              setHistory(e.target.checked)
              setPage(0)
            }}
          />{' '}
          Incluir histórico de revisões
        </label>
        <button
          className="button"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await Promise.all([
                data.refetch(),
                tests.refetch(),
                versions.refetch(),
                active.refetch(),
              ])
              setConfirmedScope(null)
            }, 'Dados atualizados; revise as versões antes de confirmar.')
          }
        >
          Atualizar dados
        </button>
      </div>
      {error ? (
        <Failure error={error} />
      ) : data.isLoading ? (
        <Loading />
      ) : data.data?.items.length ? (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Teste e versão</th>
                  <th>Regra</th>
                  <th>Revisão</th>
                  <th>Histórico</th>
                </tr>
              </thead>
              <tbody>
                {data.data.items.map((link) => (
                  <tr key={link.id}>
                    <td>
                      {link.test_name}
                      <small>
                        {link.test_id} · teste v{link.test_version}
                      </small>
                    </td>
                    <td>Sigma v{link.rule_version}</td>
                    <td>
                      {link.retired_at
                        ? 'Retirado'
                        : link.review_required
                          ? 'Revisão necessária'
                          : 'Revisado para planejamento'}
                    </td>
                    <td>
                      <details>
                        <summary>Inspecionar vínculo</summary>
                        <p>{link.rationale}</p>
                        <p>
                          Responsável: <code>{link.created_by}</code> · {date(link.created_at)}
                        </p>
                        <p className="mono">SHA-256: {link.rule_sha256}</p>
                        {link.retired_at && (
                          <p>
                            Retirado em {date(link.retired_at)} por {link.retired_by}
                          </p>
                        )}
                      </details>
                      {canEdit && !link.retired_at && (
                        <button
                          className="text-link"
                          disabled={busy}
                          onClick={() => setRetiring(link.id)}
                        >
                          Retirar vínculo
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="button" disabled={!page || busy} onClick={() => setPage(page - 1)}>
              Anterior
            </button>
            <span>
              Página {page + 1} · {data.data.total} vínculos
            </span>
            <button
              className="button"
              disabled={busy || (page + 1) * 10 >= data.data.total}
              onClick={() => setPage(page + 1)}
            >
              Próxima
            </button>
          </div>
        </>
      ) : (
        <Empty title="Nenhum vínculo registrado">
          Selecione um teste e documente a relação esperada com esta regra.
        </Empty>
      )}
      {retiring && (
        <div className="notice warning" role="alert">
          Retirar este vínculo dos próximos escopos? O histórico e as evidências serão preservados.
          <button
            className="button"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await api(`/rules/${rule.id}/test-links/${retiring}`, { method: 'DELETE' })
                setRetiring(null)
                setConfirmedScope(null)
                setPage(0)
              }, 'Vínculo retirado; histórico preservado.')
            }
          >
            Confirmar retirada
          </button>
          <button className="button" disabled={busy} onClick={() => setRetiring(null)}>
            Cancelar retirada
          </button>
        </div>
      )}
      {canEdit && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (!test || !newest || !confirmed || error || !active.data || refreshing) return
            void run(async () => {
              await api(`/rules/${rule.id}/test-links`, {
                method: 'POST',
                body: confirmedScope,
              })
              setRationale('')
              setConfirmedScope(null)
              setPage(0)
            }, 'Revisão registrada. Nenhuma regra foi implantada e nenhum teste foi executado.')
          }}
        >
          <h3>Registrar revisão de planejamento</h3>
          <label>
            Teste associado
            <select
              required
              value={testId}
              disabled={busy}
              onChange={(e) => {
                setTestId(e.target.value)
                setConfirmedScope(null)
              }}
            >
              <option value="">Selecione um teste</option>
              {tests.data?.items.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} · {t.execution_kind === 'demo' ? 'Demo sintético' : 'Linux real'} · v
                  {t.version}
                </option>
              ))}
            </select>
          </label>
          {newest && test && (
            <p className="muted-text">
              Revisando Sigma v{newest.version} / teste v{test.version}.{' '}
              {current ? 'A revisão anterior será preservada no histórico.' : 'Novo vínculo.'}
              <br />
              SHA-256: <code>{newest.sha256}</code>
            </p>
          )}
          {newest && (
            <details className="scope-details">
              <summary>Inspecionar YAML da versão atual</summary>
              <pre>{newest.content}</pre>
            </details>
          )}
          {test && (
            <p className="muted-text">
              Comportamento esperado: {test.behavior}. {test.description}
            </p>
          )}
          <label>
            Justificativa da associação
            <textarea
              required
              minLength={20}
              maxLength={4000}
              rows={3}
              value={rationale}
              disabled={busy}
              onChange={(e) => {
                setRationale(e.target.value)
                setConfirmedScope(null)
              }}
            />
          </label>
          <label className="checkbox-label">
            <input
              type="checkbox"
              required
              checked={confirmed}
              disabled={busy || !test || !newest || !!error || !active.data || refreshing}
              onChange={(e) => setConfirmedScope(e.target.checked ? fingerprint : null)}
            />{' '}
            Revisei as versões e a relação entre comportamento, logsource e regra. Este vínculo não
            comprova detecção.
          </label>
          <div className="form-actions">
            <button
              type="submit"
              className="button primary"
              disabled={busy || !confirmed || !test || !newest || !!error || refreshing}
            >
              Registrar revisão
            </button>
          </div>
        </form>
      )}
    </Modal>
  )
}
