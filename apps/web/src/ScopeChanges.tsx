import type { Comparison, ScopeChange } from './types'

export function ScopeChanges({ changes }: { changes: Comparison['scope_changes'] }) {
  const groups: [string, ScopeChange[] | null][] = [
    ['Versões do inventário Sigma', changes.rule_versions],
    ['Associações entre regras e testes', changes.rule_test_links],
    ['Definições dos testes', changes.test_definitions],
    ['Ambiente e coleta', changes.environment],
  ]
  return (
    <section className="scope-differences">
      <h3>Alterações do escopo registrado</h3>
      <p className="muted-text">
        Diferenças de configuração são contexto da avaliação; não demonstram que uma regra causou
        melhora ou regressão. Vínculos Sigma não comprovam implantação.
      </p>
      {!changes.link_context_recorded && (
        <div className="notice warning">
          O histórico anterior não registrava associações entre regras e testes. Esse contexto é
          desconhecido; não equivale a ausência de vínculos.
        </div>
      )}
      {changes.catalog_context_recorded === false && (
        <div className="notice warning">
          Uma das execuções não registrou a versão do catálogo ATT&CK. Esse contexto histórico é
          desconhecido e não será preenchido retroativamente.
        </div>
      )}
      {groups.map(
        ([label, rows]) =>
          rows && (
            <div key={label}>
              {rows.length ? (
                <details className="scope-details">
                  <summary>
                    {label} · {rows.length} alteração(ões)
                  </summary>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Campo ou identificador</th>
                          <th>Anterior</th>
                          <th>Atual</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rows.map((row) => (
                          <tr key={row.key}>
                            <td>
                              <code>{row.key}</code>
                            </td>
                            <td>
                              <pre>{JSON.stringify(row.before, null, 2)}</pre>
                            </td>
                            <td>
                              <pre>{JSON.stringify(row.after, null, 2)}</pre>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              ) : (
                <p className="muted-text">{label} · sem alterações registradas</p>
              )}
            </div>
          ),
      )}
    </section>
  )
}
