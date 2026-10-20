import { useState } from 'react'
import { CalendarClock, Pause, Plus, ShieldCheck, XCircle } from 'lucide-react'
import {
  api,
  Badge,
  date,
  Empty,
  Failure,
  Go,
  Loading,
  Modal,
  navigate,
  PageHeading,
  Panel,
  Submit,
  useAction,
  useData,
} from './lib'
import type { Campaign, Page, Schedule, ScheduleDetail, ScheduleOccurrence, User } from './types'

export function Scheduling({ user, id }: { user: User; id?: string }) {
  const [creating, setCreating] = useState(false),
    [offset, setOffset] = useState(0)
  const list = useData<Page<Schedule>>(`/schedules?limit=25&offset=${offset}`, 3000)
  const campaigns = useData<Page<Campaign>>('/campaigns?limit=1000')
  return (
    <>
      <PageHeading
        eyebrow="AUTOMAÇÃO CONTROLADA"
        title="Agendamentos"
        description="Campanhas Demo recorrentes, com autorização explícita e limites persistentes."
        action={
          user.role !== 'viewer' && (
            <button className="button primary" onClick={() => setCreating(true)}>
              <Plus size={17} /> Novo agendamento
            </button>
          )
        }
      />
      <div className="notice">
        <CalendarClock size={19} /> Dados sintéticos. Cada horário executado ou descartado consome o
        limite aprovado. Atrasos acima de 30 segundos e laboratório ocupado não geram execução
        retroativa.
      </div>
      <Panel
        title="Planos de execução"
        subtitle="A criação não autoriza execução. Somente administradores podem aprovar e retomar planos."
      >
        {list.isLoading ? (
          <Loading />
        ) : list.error ? (
          <Failure error={list.error} />
        ) : list.data?.items.length ? (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Campanha</th>
                    <th>Estado</th>
                    <th>Próximo horário</th>
                    <th>Consumo</th>
                    <th>Cadência</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>
                          {campaigns.data?.items.find((c) => c.id === s.campaign_id)?.name ??
                            s.campaign_id.slice(0, 8)}
                        </strong>
                        <small>{s.id.slice(0, 8)} · Demo Lab</small>
                      </td>
                      <td>
                        <Badge value={s.state} />
                      </td>
                      <td>{s.state === 'ACTIVE' ? date(s.next_due_at) : '—'}</td>
                      <td>
                        {s.occurrences_count} / {s.max_occurrences} horários
                      </td>
                      <td>{s.interval_seconds} s</td>
                      <td>
                        <Go to={`schedules/${s.id}`}>Detalhes</Go>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button
                className="button"
                disabled={!offset}
                onClick={() => setOffset(Math.max(0, offset - 25))}
              >
                Anterior
              </button>
              <span>
                {offset + 1}–{Math.min(offset + 25, list.data.total)} de {list.data.total}
              </span>
              <button
                className="button"
                disabled={offset + 25 >= list.data.total}
                onClick={() => setOffset(offset + 25)}
              >
                Próxima
              </button>
            </div>
          </>
        ) : (
          <Empty title="Nenhum agendamento criado">
            Crie uma campanha e defina o período, a cadência e o limite de horários.
          </Empty>
        )}
      </Panel>
      {id && <ScheduleView id={id} user={user} />}
      {creating && <ScheduleForm onClose={() => setCreating(false)} />}
    </>
  )
}

function localTime(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 19)
}

export function ScheduleForm({ onClose }: { onClose: () => void }) {
  const campaigns = useData<Page<Campaign>>('/campaigns?limit=1000'),
    { busy, run } = useAction()
  const [campaign, setCampaign] = useState(''),
    [interval, setInterval] = useState(3600),
    [limit, setLimit] = useState(5),
    [duration, setDuration] = useState(60),
    [start, setStart] = useState(() => localTime(new Date(Date.now() + 120000))),
    [end, setEnd] = useState(() => localTime(new Date(Date.now() + 86400000))),
    [error, setError] = useState('')
  return (
    <Modal title="Novo agendamento Demo" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (
            interval < duration ||
            new Date(end) <= new Date(start) ||
            new Date(start).getTime() <= Date.now()
          ) {
            setError('Verifique o período futuro e use intervalo maior ou igual à duração máxima.')
            return
          }
          setError('')
          void run(async () => {
            const created = await api<Schedule>('/schedules', {
              method: 'POST',
              body: JSON.stringify({
                campaign_id: campaign,
                interval_seconds: interval,
                max_occurrences: limit,
                max_duration_seconds: duration,
                starts_at: new Date(start).toISOString(),
                ends_at: new Date(end).toISOString(),
              }),
            })
            onClose()
            navigate(`schedules/${created.id}`)
          }, 'Plano criado. Aguarda aprovação explícita de um administrador.')
        }}
      >
        {campaigns.error && <Failure error={campaigns.error} />}
        <label>
          Campanha
          <select required value={campaign} onChange={(e) => setCampaign(e.target.value)}>
            <option value="">Selecione a campanha Demo</option>
            {campaigns.data?.items.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        <div className="form-grid">
          <label>
            Início (horário local)
            <input
              required
              type="datetime-local"
              step="1"
              value={start}
              onChange={(e) => setStart(e.target.value)}
            />
          </label>
          <label>
            Fim da autorização (horário local)
            <input
              required
              type="datetime-local"
              step="1"
              value={end}
              onChange={(e) => setEnd(e.target.value)}
            />
          </label>
        </div>
        <div className="form-grid">
          <label>
            Intervalo em segundos
            <input
              required
              type="number"
              min="60"
              max="2592000"
              value={interval}
              onChange={(e) => setInterval(Number(e.target.value))}
            />
          </label>
          <label>
            Máximo de horários
            <input
              required
              type="number"
              min="1"
              max="100"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            />
          </label>
        </div>
        <label>
          Duração máxima por execução (segundos)
          <input
            required
            type="number"
            min="10"
            max="300"
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
          />
        </label>
        <p className="muted">
          Início em até 30 dias; fim em até 90 dias. Horários ancorados no início, sem acumular
          execuções. Limite global: 64 planos abertos e 16 ativos.
        </p>
        {error && (
          <div className="notice danger" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Cancelar
          </button>
          <Submit busy={busy || !campaign}>Criar plano</Submit>
        </div>
      </form>
    </Modal>
  )
}

function ScheduleView({ id, user }: { id: string; user: User }) {
  const data = useData<ScheduleDetail>(`/schedules/${id}`, 3000),
    [offset, setOffset] = useState(0)
  const history = useData<Page<ScheduleOccurrence>>(
    `/schedules/${id}/occurrences?limit=25&offset=${offset}`,
    3000,
  )
  const [intent, setIntent] = useState<'approve' | 'pause' | 'revoke' | null>(null),
    [confirmed, setConfirmed] = useState(false),
    { busy, run } = useAction()
  if (data.isLoading) return <Loading />
  if (data.error) return <Failure error={data.error} />
  if (!data.data) return null
  const s = data.data,
    canApprove = ['PENDING_APPROVAL', 'PAUSED'].includes(s.state) && user.role === 'administrator'
  return (
    <>
      <Panel
        title={`Plano ${s.id.slice(0, 8)}`}
        subtitle="Escopo e limites imutáveis. Uma mudança exige novo plano."
      >
        <div className="schedule-detail">
          <div className="toolbar">
            <Badge value={s.state} />
            <span className="subtle-tag">SINTÉTICO</span>
          </div>
          <div className="schedule-facts">
            <p>
              <small>Período aprovado</small>
              {date(s.starts_at)} → {date(s.ends_at)}
            </p>
            <p>
              <small>Cadência / duração máxima</small>
              {s.interval_seconds} s / {s.max_duration_seconds} s
            </p>
            <p>
              <small>Orçamento consumido</small>
              {s.occurrences_count} de {s.max_occurrences} horários
            </p>
            <p>
              <small>Ambiente</small>Demo · versão {s.scope.environment_version}
            </p>
          </div>
          <p>{s.scope.test_definitions.map((t) => `${t.name} (v${t.version})`).join(' · ')}</p>
          <p className="muted">
            Versões de regras no snapshot: {Object.keys(s.scope.rule_versions).length}. Cadastro
            Sigma não significa implantação no SIEM.
          </p>
          <details>
            <summary>Hash e plano autorizado</summary>
            <pre>
              {JSON.stringify({ plan_hash: s.plan_hash, ...s.plan, scope: s.scope }, null, 2)}
            </pre>
          </details>
          {s.reason && (
            <div className={`notice ${s.state === 'INVALIDATED' ? 'danger' : ''}`}>{s.reason}</div>
          )}
          <div className="toolbar">
            {canApprove && (
              <button
                className="button primary"
                onClick={() => {
                  setConfirmed(false)
                  setIntent('approve')
                }}
              >
                <ShieldCheck size={16} /> Revisar autorização recorrente
              </button>
            )}
            {user.role !== 'viewer' && ['ACTIVE', 'PENDING_APPROVAL'].includes(s.state) && (
              <button className="button" onClick={() => setIntent('pause')}>
                <Pause size={16} /> Pausar plano
              </button>
            )}
            {user.role === 'administrator' && s.state !== 'REVOKED' && (
              <button className="button danger" onClick={() => setIntent('revoke')}>
                <XCircle size={16} /> Revogar autorização
              </button>
            )}
          </div>
          {s.authorizations.length > 0 && (
            <details>
              <summary>Histórico de autorizações ({s.authorizations.length})</summary>
              {s.authorizations.map((g) => (
                <p key={g.id}>
                  <code>{g.id}</code> · {date(g.created_at)} ·{' '}
                  {g.revoked_at
                    ? `revogada em ${date(g.revoked_at)}`
                    : `validade até ${date(g.expires_at)}`}
                </p>
              ))}
            </details>
          )}
        </div>
      </Panel>
      <Panel
        title="Histórico de horários"
        subtitle="Cada ocorrência preserva a autorização de origem. Descartes não produzem evidências de execução."
      >
        {history.isLoading ? (
          <Loading />
        ) : history.error ? (
          <Failure error={history.error} />
        ) : history.data?.items.length ? (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Horário previsto</th>
                    <th>Resultado do disparo</th>
                    <th>Justificativa</th>
                    <th>Execução</th>
                  </tr>
                </thead>
                <tbody>
                  {history.data.items.map((o) => (
                    <tr key={o.id}>
                      <td>{date(o.scheduled_for)}</td>
                      <td>
                        <Badge value={o.status} />
                      </td>
                      <td>
                        {o.reason}
                        <small>Autorização {o.authorization_id.slice(0, 8)}</small>
                      </td>
                      <td>
                        {o.run_id ? (
                          <Go to={`executions/${o.run_id}`}>Ver execução</Go>
                        ) : (
                          'Não executado'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button
                className="button"
                disabled={!offset}
                onClick={() => setOffset(Math.max(0, offset - 25))}
              >
                Anterior
              </button>
              <span>{history.data.total} ocorrências</span>
              <button
                className="button"
                disabled={offset + 25 >= history.data.total}
                onClick={() => setOffset(offset + 25)}
              >
                Próxima
              </button>
            </div>
          </>
        ) : (
          <Empty title="Nenhum horário processado">
            O worker só dispara planos ativos dentro da janela autorizada.
          </Empty>
        )}
      </Panel>
      {intent && (
        <Modal
          title={
            intent === 'approve'
              ? 'Autorizar execuções recorrentes'
              : intent === 'pause'
                ? 'Pausar agendamento'
                : 'Revogar agendamento'
          }
          onClose={() => setIntent(null)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void run(
                async () => {
                  await api(`/schedules/${id}/${intent}`, {
                    method: 'POST',
                    body: JSON.stringify(
                      intent === 'approve'
                        ? { confirm_plan_hash: s.plan_hash, confirm_automatic_execution: true }
                        : { confirm: true },
                    ),
                  })
                  setIntent(null)
                },
                intent === 'approve'
                  ? 'Autorização registrada. Worker pode iniciar automaticamente dentro dos limites.'
                  : 'Autorização encerrada. Execuções ativas observarão cancelamento e farão cleanup.',
              )
            }}
          >
            {intent === 'approve' ? (
              <>
                <p>
                  Autorize o início automático das simulações Demo sem novas confirmações por
                  execução.
                </p>
                <ul>
                  <li>Cadência: {s.interval_seconds} segundos.</li>
                  <li>
                    Restam até {s.max_occurrences - s.occurrences_count} horários, incluindo
                    descartes.
                  </li>
                  <li>
                    Duração máxima: {s.max_duration_seconds} segundos por execução, limitada pelo
                    fim da autorização.
                  </li>
                  <li>
                    Janela: {date(s.starts_at)} até {date(s.ends_at)}.
                  </li>
                  <li>Pausar exige nova aprovação para retomar e preserva o consumo.</li>
                </ul>
                <code className="hash">{s.plan_hash}</code>
                <label className="check-row">
                  <input
                    type="checkbox"
                    required
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.target.checked)}
                  />{' '}
                  Revisei o escopo e autorizo a execução automática deste plano sintético.
                </label>
              </>
            ) : (
              <p>
                As execuções na fila serão canceladas. Uma etapa já iniciada pode terminar antes do
                cancelamento cooperativo e cleanup.{' '}
                {intent === 'pause'
                  ? 'Retomar exige nova aprovação administrativa.'
                  : 'Esta revogação é definitiva; crie outro plano se necessário.'}
              </p>
            )}
            <div className="form-actions">
              <button type="button" className="button" onClick={() => setIntent(null)}>
                Voltar
              </button>
              <Submit busy={busy || (intent === 'approve' && !confirmed)}>
                {intent === 'approve'
                  ? 'Autorizar plano Demo'
                  : intent === 'pause'
                    ? 'Confirmar pausa'
                    : 'Confirmar revogação'}
              </Submit>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
