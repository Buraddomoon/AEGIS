import { useState } from 'react'
import { LinuxRegistration } from './LinuxRegistration'
import { WazuhBinding } from './WazuhBinding'
import { RuleTestLinks } from './RuleTestLinks'
import { RuleAnalysis } from './RuleAnalysis'
import {
  CheckCircle2,
  FileCode2,
  FlaskConical,
  History,
  LockKeyhole,
  Plus,
  Radio,
  Upload,
  Users,
} from 'lucide-react'
import {
  api,
  Badge,
  date,
  Empty,
  Failure,
  Loading,
  Modal,
  PageHeading,
  Panel,
  Submit,
  useAction,
  useData,
} from './lib'
import type { Audit, Connectors, Lab, Page, Rule, RuleVersion, User } from './types'

export function Laboratories({ user }: { user: User }) {
  const data = useData<Page<Lab & { active_run_state: string | null }>>('/labs', 3000),
    { busy, run } = useAction(),
    [registering, setRegistering] = useState(false),
    [telemetryLab, setTelemetryLab] = useState<Lab | null>(null),
    [selected, setSelected] = useState<string | null>(null)
  return (
    <>
      <PageHeading
        eyebrow="ESCOPO AUTORIZADO"
        title="Laboratórios"
        action={
          user.role === 'administrator' && (
            <button className="button primary" onClick={() => setRegistering(true)}>
              <Plus size={17} />
              Registrar Linux Lab
            </button>
          )
        }
        description="Identidade, versão de ambiente e autorização explícita para cada laboratório."
      />
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        data.data?.items.map((l) => (
          <Panel className="lab-panel" key={l.id}>
            <div className="lab-title">
              <span className="test-icon">
                <FlaskConical size={25} />
              </span>
              <div>
                <h2>{l.name}</h2>
                <p>{l.description}</p>
              </div>
              <Badge value={l.connection_status} />
            </div>
            <div className="lab-details">
              <div>
                <small>AUTORIZAÇÃO</small>
                <strong>{l.authorized ? 'Autorizado' : 'Revogada'}</strong>
              </div>
              <div>
                <small>RESPONSÁVEL</small>
                <strong>{l.owner}</strong>
              </div>
              <div>
                <small>VERSÃO DO AMBIENTE</small>
                <strong>v{l.environment_version}</strong>
              </div>
              <div>
                <small>CAPACIDADE</small>
                <strong>
                  {l.synthetic
                    ? 'Adaptadores sintéticos'
                    : l.execution_capability === 'linux-marker-only'
                      ? 'Marcador Linux revisado'
                      : 'Desconectado'}
                </strong>
              </div>
            </div>
            <div className="notice">
              <LockKeyhole size={18} />
              {l.isolation}
            </div>
            <p className="mono muted-text">ID {l.id}</p>
            {!l.synthetic && (
              <button className="button" onClick={() => setTelemetryLab(l)}>
                Revisar coleta Wazuh
              </button>
            )}
            {!l.synthetic && (
              <button className="text-link" onClick={() => setSelected(l.id)}>
                Histórico de verificações mTLS
              </button>
            )}
            {l.active_run_id && (
              <p>
                Laboratório reservado:{' '}
                <a href={`#executions/${l.active_run_id}`} className="text-link">
                  {l.active_run_id.slice(0, 8)} · {l.active_run_state}
                </a>
              </p>
            )}
            {user.role === 'administrator' && (
              <div className="inline-actions">
                {!l.synthetic && (
                  <button
                    className="button"
                    disabled={busy}
                    onClick={() =>
                      void run(
                        () =>
                          api(`/labs/${l.id}/preflight`, {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true }),
                          }),
                        'Preflight registrado; consulte o resultado da verificação.',
                      )
                    }
                  >
                    Verificar mTLS (sem execução)
                  </button>
                )}
                <button
                  className="button"
                  disabled={busy}
                  onClick={() =>
                    void run(
                      () =>
                        api(`/labs/${l.id}/authorization`, {
                          method: 'PATCH',
                          body: JSON.stringify({ authorized: !l.authorized }),
                        }),
                      'Autorização atualizada; aprovações anteriores podem exigir nova revisão.',
                    )
                  }
                >
                  {l.authorized
                    ? 'Revogar autorização'
                    : `Autorizar ${l.synthetic ? 'Demo Lab' : 'Linux Lab'}`}
                </button>
                {l.active_run_state === 'CLEANUP_FAILED' && (
                  <button
                    className="button"
                    disabled={busy}
                    onClick={() =>
                      void run(
                        () =>
                          api(`/labs/${l.id}/recover`, {
                            method: 'POST',
                            body: JSON.stringify({ confirm: true }),
                          }),
                        'Recuperação registrada; laboratório liberado após confirmação de cleanup.',
                      )
                    }
                  >
                    {l.synthetic
                      ? 'Confirmar revisão e liberar laboratório'
                      : 'Verificar cleanup original e liberar'}
                  </button>
                )}
              </div>
            )}
          </Panel>
        ))
      )}
      <div className="notice">
        <Radio size={18} />
        Linux é opt-in e aceita somente o marcador benigno fixado na implantação. Sem coleta SIEM, o
        resultado defensivo é inconclusivo. Windows e agendamentos Linux permanecem indisponíveis.
      </div>
      {telemetryLab && (
        <WazuhBinding lab={telemetryLab} user={user} onClose={() => setTelemetryLab(null)} />
      )}
      {registering && <LinuxRegistration onClose={() => setRegistering(false)} />}
      {selected && <VerificationHistory id={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

function VerificationHistory({ id, onClose }: { id: string; onClose: () => void }) {
  const data = useData<
    Page<{ id: string; success: boolean; reason: string; expires_at: string; created_at: string }>
  >(`/labs/${id}/verifications`)
  return (
    <Modal title="Verificações do runner" onClose={onClose}>
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : data.data?.items.length ? (
        data.data.items.map((v) => (
          <article key={v.id}>
            <strong>{v.success ? 'Preflight confirmado' : 'Preflight falhou'}</strong>
            <p>{v.reason}</p>
            <p>
              {date(v.created_at)} · validade {date(v.expires_at)}
            </p>
          </article>
        ))
      ) : (
        <Empty title="Nenhuma verificação registrada" />
      )}
    </Modal>
  )
}

export function Rules({ user }: { user: User }) {
  const data = useData<Page<Rule>>('/rules?limit=1000'),
    [creating, setCreating] = useState(false),
    [selected, setSelected] = useState<Rule | null>(null),
    [linked, setLinked] = useState<Rule | null>(null),
    [analyzed, setAnalyzed] = useState<Rule | null>(null)
  return (
    <>
      <PageHeading
        eyebrow="DETECTION ENGINEERING"
        title="Regras de detecção"
        description="Inventário Sigma com validação de sintaxe e histórico imutável de versões."
        action={
          user.role !== 'viewer' && (
            <button className="button primary" onClick={() => setCreating(true)}>
              <Plus size={17} />
              Importar regra Sigma
            </button>
          )
        }
      />
      <div className="notice">
        <FileCode2 size={18} />
        Parsing com pySigma. Sintaxe válida não comprova eficácia, conversão compatível ou
        implantação no Wazuh.
      </div>
      <Panel>
        {data.isLoading ? (
          <Loading />
        ) : data.error ? (
          <Failure error={data.error} />
        ) : data.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Regra</th>
                  <th>Versão</th>
                  <th>Estado</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.data.items.map((r) => (
                  <tr key={r.id}>
                    <td className="table-title">
                      {r.title}
                      <small>{r.sigma_id}</small>
                    </td>
                    <td>v{r.latest_version}</td>
                    <td>
                      <span className="subtle-tag">Sintaxe validada · não implantada</span>
                    </td>
                    <td>
                      <button className="text-link" onClick={() => setSelected(r)}>
                        <History size={16} />
                        Versões e comparação
                      </button>
                      <button className="text-link" onClick={() => setAnalyzed(r)}>
                        Análise estática
                      </button>
                      <button className="text-link" onClick={() => setLinked(r)}>
                        Testes e revisões
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma regra cadastrada">
            Importe um YAML Sigma para validar e versionar uma regra.
          </Empty>
        )}
      </Panel>
      {creating && <SigmaForm onClose={() => setCreating(false)} />}{' '}
      {selected && <RuleHistory rule={selected} onClose={() => setSelected(null)} />}
      {analyzed && <RuleAnalysis rule={analyzed} onClose={() => setAnalyzed(null)} />}
      {linked && <RuleTestLinks rule={linked} user={user} onClose={() => setLinked(null)} />}
    </>
  )
}

function SigmaForm({ onClose }: { onClose: () => void }) {
  const [content, setContent] = useState(''),
    [fileError, setFileError] = useState(''),
    { busy, run } = useAction()
  return (
    <Modal title="Importar YAML Sigma" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void run(async () => {
            await api('/rules', { method: 'POST', body: JSON.stringify({ content }) })
            onClose()
          }, 'Sintaxe validada pelo pySigma; versão registrada. Nenhuma regra foi implantada.')
        }}
      >
        <label className="file-label">
          <Upload size={18} />
          Selecionar arquivo YAML
          <input
            type="file"
            accept=".yaml,.yml"
            onChange={async (e) => {
              const file = e.target.files?.[0]
              setFileError('')
              if (!file) return
              if (file.size > 65536) {
                setFileError('Arquivo excede 64 KiB.')
                return
              }
              setContent(await file.text())
            }}
          />
        </label>
        {fileError && (
          <div className="notice danger" role="alert">
            {fileError}
          </div>
        )}
        <label>
          Conteúdo da regra
          <textarea
            className="code-input"
            rows={16}
            required
            value={content}
            maxLength={65536}
            onChange={(e) => setContent(e.target.value)}
            placeholder={
              'title: Minha regra\nid: UUID\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: linux\ndetection:\n  selection:\n    Image|endswith: /sh\n  condition: selection'
            }
          />
        </label>
        <p className="muted-text">
          Um documento por importação, máximo 64 KiB, sem aliases YAML. Até 6 modificadores sem
          repetição por campo, com orçamento de expansão. Para criar nova versão, mantenha o mesmo
          UUID.
        </p>
        <div className="form-actions">
          <button className="button" type="button" onClick={onClose}>
            Cancelar
          </button>
          <Submit busy={busy}>Validar e salvar</Submit>
        </div>
      </form>
    </Modal>
  )
}

function RuleHistory({ rule, onClose }: { rule: Rule; onClose: () => void }) {
  const data = useData<Page<RuleVersion>>(`/rules/${rule.id}/versions`),
    [previous, setPrevious] = useState('')
  const newest = data.data?.items[0],
    older = data.data?.items.find((v) => String(v.version) === previous) ?? data.data?.items[1]
  return (
    <Modal title={`Versões · ${rule.title}`} onClose={onClose}>
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        newest && (
          <>
            <p className="muted-text">
              Associações ATT&CK: {newest.techniques.join(', ') || 'Nenhuma'} · não implantada.
            </p>
            {data.data!.items.length > 1 && (
              <label>
                Comparar versão anterior
                <select
                  value={previous || String(older?.version)}
                  onChange={(e) => setPrevious(e.target.value)}
                >
                  {data.data!.items.slice(1).map((v) => (
                    <option value={v.version} key={v.id}>
                      v{v.version} · {date(v.created_at)}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <div className="version-grid">
              {older && (
                <div>
                  <h3>Anterior · v{older.version}</h3>
                  <pre>{older.content}</pre>
                </div>
              )}
              <div>
                <h3>Atual · v{newest.version}</h3>
                <pre>{newest.content}</pre>
              </div>
            </div>
            <p className="mono muted-text">
              SHA-256 v{newest.version}: {newest.sha256}
            </p>
          </>
        )
      )}
    </Modal>
  )
}

export function Settings({ user }: { user: User }) {
  return (
    <>
      <PageHeading
        eyebrow="WORKSPACE E CONTROLES"
        title="Configurações"
        description="Integrações, identidade e auditoria. Permissões verificadas pelo backend."
      />
      <IntegrationSettings user={user} />
      {user.role === 'administrator' ? (
        <>
          <UserSettings />
          <AuditLog />
        </>
      ) : (
        <Panel>
          <Empty title="Administração restrita">
            Gerenciamento de usuários e consulta à auditoria exigem o papel Administrador.
          </Empty>
        </Panel>
      )}
    </>
  )
}

function IntegrationSettings({ user }: { user: User }) {
  const data = useData<Connectors>('/connectors', 5000),
    { busy, run } = useAction(),
    [tested, setTested] = useState('')
  return (
    <Panel
      title="Integrações"
      subtitle="Credenciais e destinos são configurados por ambiente; nunca enviados pelo navegador."
    >
      {data.error ? (
        <Failure error={data.error} />
      ) : (
        data.data?.items.map((c) => (
          <div className="integration-row" key={c.id}>
            <span className="connector-icon">
              <Radio size={22} />
            </span>
            <div>
              <strong>{c.name}</strong>
              <p>{c.description}</p>
              <Badge value={c.status} />
            </div>
            {c.id === 'wazuh' && user.role === 'administrator' && (
              <button
                className="button"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const result = await api<{ status: string; version: string }>(
                      '/connectors/wazuh/test',
                      { method: 'POST' },
                    )
                    setTested(`Último teste: ${result.status} · versão ${result.version}`)
                  }, 'Consulta de conectividade concluída. Não valida ingestão nem detecção.')
                }
              >
                <CheckCircle2 size={16} />
                Testar conexão configurada
              </button>
            )}
          </div>
        ))
      )}
      {tested && <div className="notice">{tested}</div>}
      <div className="panel-footnote">
        Wazuh não é necessário para o Demo Mode. O adaptador real possui testes locais com respostas
        anonimizadas; conexão externa depende de ambiente autorizado.
      </div>
    </Panel>
  )
}

function UserSettings() {
  const data = useData<Page<User>>('/users?limit=1000'),
    [creating, setCreating] = useState(false),
    [username, setUsername] = useState(''),
    [password, setPassword] = useState(''),
    [role, setRole] = useState('viewer'),
    { busy, run } = useAction()
  return (
    <Panel
      title="Usuários e permissões"
      subtitle="Workspace único; todos os usuários autenticados compartilham os dados de consulta."
      action={
        <button className="button" onClick={() => setCreating(true)}>
          <Users size={16} />
          Adicionar usuário
        </button>
      }
    >
      {data.error ? (
        <Failure error={data.error} />
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Usuário</th>
                <th>Papel</th>
                <th>Situação</th>
              </tr>
            </thead>
            <tbody>
              {data.data?.items.map((u) => (
                <tr key={u.id}>
                  <td>{u.username}</td>
                  <td>
                    <Badge value={u.role} />
                  </td>
                  <td>{u.active ? 'Ativo' : 'Desativado'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && (
        <Modal title="Adicionar usuário" onClose={() => setCreating(false)}>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void run(async () => {
                await api('/users', {
                  method: 'POST',
                  body: JSON.stringify({ username, password, role }),
                })
                setPassword('')
                setUsername('')
                setCreating(false)
              }, 'Usuário criado.')
            }}
          >
            <label>
              Usuário
              <input
                required
                minLength={3}
                maxLength={80}
                pattern="[a-zA-Z0-9_.@\-]+"
                autoComplete="off"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <label>
              Senha inicial
              <input
                type="password"
                required
                minLength={12}
                maxLength={128}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <label>
              Papel
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="viewer">Visualizador</option>
                <option value="operator">Operador</option>
                <option value="administrator">Administrador</option>
              </select>
            </label>
            <p className="muted-text">
              Admin aprova e configura; Operador cria e executa escopos aprovados; Visualizador
              consulta.
            </p>
            <div className="form-actions">
              <Submit busy={busy}>Criar usuário</Submit>
            </div>
          </form>
        </Modal>
      )}
    </Panel>
  )
}

function AuditLog() {
  const [page, setPage] = useState(0),
    data = useData<Page<Audit>>(`/audit?limit=25&offset=${page * 25}`)
  return (
    <Panel title="Auditoria" subtitle="Ações importantes e transições, sem senhas ou tokens.">
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Horário</th>
                  <th>Ação</th>
                  <th>Recurso</th>
                  <th>Detalhes</th>
                </tr>
              </thead>
              <tbody>
                {data.data?.items.map((a) => (
                  <tr key={a.id}>
                    <td>{date(a.created_at)}</td>
                    <td>
                      <code>{a.action}</code>
                    </td>
                    <td>
                      <code>{a.resource_id.slice(0, 12)}</code>
                    </td>
                    <td>
                      <details>
                        <summary>Inspecionar</summary>
                        <pre>{JSON.stringify(a.details, null, 2)}</pre>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="button" disabled={!page} onClick={() => setPage(page - 1)}>
              Anterior
            </button>
            <span>
              Página {page + 1} · {data.data?.total} registros
            </span>
            <button
              className="button"
              disabled={(page + 1) * 25 >= (data.data?.total ?? 0)}
              onClick={() => setPage(page + 1)}
            >
              Próxima
            </button>
          </div>
        </>
      )}
    </Panel>
  )
}
