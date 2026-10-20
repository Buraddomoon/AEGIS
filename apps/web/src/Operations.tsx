import { useState } from 'react'
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Download,
  FileJson,
  Filter,
  Layers,
  Play,
  Plus,
  Repeat2,
  ShieldCheck,
  Square,
  XCircle,
} from 'lucide-react'
import {
  api,
  Badge,
  date,
  downloadReport,
  Empty,
  Failure,
  Go,
  labels,
  Loading,
  Modal,
  navigate,
  PageHeading,
  Panel,
  Submit,
  terminal,
  useAction,
  useData,
} from './lib'
import type {
  Campaign,
  Comparison,
  Coverage,
  EventRecord,
  Lab,
  Page,
  Run,
  RunDetail,
  Test,
  User,
} from './types'

export function Campaigns({ user }: { user: User }) {
  const data = useData<Page<Campaign>>('/campaigns?limit=1000'),
    [creating, setCreating] = useState(location.hash.includes('/new')),
    { busy, run } = useAction()
  const request = (id: string) =>
    run(async () => {
      const r = await api<Run>(`/campaigns/${id}/runs`, {
        method: 'POST',
        body: JSON.stringify({ idempotency_key: crypto.randomUUID().replaceAll('-', '') }),
      })
      navigate(`executions/${r.id}`)
    }, 'Solicitação criada. Revise o escopo antes de aprovar.')
  return (
    <>
      <PageHeading
        eyebrow="PLANEJAR E VALIDAR"
        title="Campanhas"
        description="Organize simulações em um escopo reproduzível e explicitamente aprovado."
        action={
          user.role !== 'viewer' && (
            <button className="button primary" onClick={() => setCreating(true)}>
              <Plus size={17} />
              Nova campanha
            </button>
          )
        }
      />
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : data.data?.items.length ? (
        <div className="campaign-grid">
          {data.data.items.map((c) => (
            <Panel className="campaign-card" key={c.id}>
              <div className="test-top">
                <span className="test-icon">
                  <Layers size={23} />
                </span>
                <span className="subtle-tag">Demo Lab</span>
              </div>
              <h2>{c.name}</h2>
              <p>{c.objective}</p>
              <div className="campaign-meta">
                <span>{c.test_ids.length} simulações</span>
                <span>{date(c.created_at)}</span>
              </div>
              <div className="campaign-actions">
                <Go to={`executions?campaign=${c.id}`}>Histórico</Go>
                {user.role !== 'viewer' && (
                  <button className="button" disabled={busy} onClick={() => void request(c.id)}>
                    <Play size={15} />
                    Solicitar execução
                  </button>
                )}
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <Panel>
          <Empty title="Sua próxima validação começa aqui">
            Crie uma campanha e selecione as simulações do Demo Lab.
          </Empty>
        </Panel>
      )}
      {creating && <CampaignForm onClose={() => setCreating(false)} />}
    </>
  )
}

function CampaignForm({ onClose }: { onClose: () => void }) {
  const labs = useData<Page<Lab>>('/labs'),
    tests = useData<Page<Test>>('/tests'),
    [name, setName] = useState(''),
    [objective, setObjective] = useState(''),
    [lab, setLab] = useState(''),
    [selected, setSelected] = useState<string[]>([]),
    { busy, run } = useAction()
  return (
    <Modal title="Nova campanha" onClose={onClose}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void run(async () => {
            await api('/campaigns', {
              method: 'POST',
              body: JSON.stringify({ name, objective, laboratory_id: lab, test_ids: selected }),
            })
            onClose()
            navigate('campaigns')
          }, 'Campanha criada. Solicite uma execução para iniciar a revisão.')
        }}
      >
        <label>
          Nome da campanha
          <input
            required
            minLength={3}
            maxLength={160}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Validação de detecção de endpoints"
          />
        </label>
        <label>
          Objetivo
          <textarea
            required
            minLength={5}
            maxLength={4000}
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="Descreva o que será avaliado e as limitações do escopo…"
          />
        </label>
        <label>
          Laboratório
          <select required value={lab} onChange={(e) => setLab(e.target.value)}>
            <option value="">Selecione o ambiente</option>
            {labs.data?.items
              .filter((l) => l.authorized)
              .map((l) => (
                <option value={l.id} key={l.id}>
                  {l.name} · versão {l.environment_version} · sintético
                </option>
              ))}
          </select>
        </label>
        <fieldset>
          <legend>Simulações do escopo</legend>
          {tests.data?.items.map((t) => (
            <label className="checkbox-label" key={t.id}>
              <input
                type="checkbox"
                checked={selected.includes(t.id)}
                onChange={(e) =>
                  setSelected(
                    e.target.checked ? [...selected, t.id] : selected.filter((x) => x !== t.id),
                  )
                }
              />
              <span>
                {t.name}
                <small>{t.technique_id ?? 'Sem associação ATT&CK'} · sintético</small>
              </span>
            </label>
          ))}
        </fieldset>
        {(labs.error || tests.error) && <Failure error={(labs.error || tests.error)!} />}
        <p className="muted-text">
          O escopo da campanha é imutável. Cada repetição requer uma nova aprovação.
        </p>
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Cancelar
          </button>
          <button className="button primary" type="submit" disabled={busy || !selected.length}>
            Criar campanha
            <ArrowRight size={16} />
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function Executions() {
  const campaign = new URLSearchParams(location.hash.split('?')[1] ?? '').get('campaign'),
    [filter, setFilter] = useState(''),
    [page, setPage] = useState(0)
  const data = useData<Page<Run>>(
      `/executions?limit=25&offset=${page * 25}${filter ? `&state=${filter}` : ''}${campaign ? `&campaign_id=${campaign}` : ''}`,
      2500,
    ),
    campaigns = useData<Page<Campaign>>('/campaigns?limit=1000')
  return (
    <>
      <PageHeading
        eyebrow="RASTREABILIDADE DE PONTA A PONTA"
        title="Execuções"
        description="Acompanhe estados, decisões de validação, eventos originais e procedimentos de limpeza."
      />
      <div className="toolbar">
        <Filter size={17} />
        <select
          aria-label="Filtrar estado"
          value={filter}
          onChange={(e) => {
            setFilter(e.target.value)
            setPage(0)
          }}
        >
          <option value="">Todos os estados</option>
          {['PENDING_APPROVAL', 'QUEUED', 'RUNNING', ...terminal].map((s) => (
            <option value={s} key={s}>
              {labels[s]}
            </option>
          ))}
        </select>
        {campaign && (
          <a href="#executions" className="text-link">
            Remover filtro de campanha
          </a>
        )}
      </div>
      <Panel>
        {data.isLoading ? (
          <Loading />
        ) : data.error ? (
          <Failure error={data.error} />
        ) : data.data?.items.length ? (
          <>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Campanha / execução</th>
                    <th>Estado</th>
                    <th>Início</th>
                    <th>Conclusão</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {data.data.items.map((r) => (
                    <tr key={r.id}>
                      <td>
                        <a href={`#executions/${r.id}`} className="table-title">
                          {campaigns.data?.items.find((c) => c.id === r.campaign_id)?.name ??
                            'Campanha'}
                          <small>{r.id.slice(0, 8)} · sintético</small>
                        </a>
                      </td>
                      <td>
                        <Badge value={r.state} />
                      </td>
                      <td>{date(r.started_at)}</td>
                      <td>{date(r.ended_at)}</td>
                      <td>
                        <Go to={`executions/${r.id}`}>Detalhes</Go>
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
                {data.data.total} execuções · página {page + 1}
              </span>
              <button
                className="button"
                disabled={(page + 1) * 25 >= data.data.total}
                onClick={() => setPage(page + 1)}
              >
                Próxima
              </button>
            </div>
          </>
        ) : (
          <Empty title="Nenhuma execução no filtro atual" />
        )}
      </Panel>
    </>
  )
}

export function ExecutionDetail({ id, user }: { id: string; user: User }) {
  const data = useData<RunDetail>(`/executions/${id}`, 1500),
    [review, setReview] = useState(false),
    [event, setEvent] = useState<EventRecord | null>(null),
    { busy, run } = useAction()
  if (data.isLoading) return <Loading />
  if (data.error) return <Failure error={data.error} />
  const r = data.data!,
    active = !terminal.includes(r.state),
    pending = r.state === 'PENDING_APPROVAL'
  const repeat = () =>
    run(async () => {
      const next = await api<Run>(`/campaigns/${r.campaign_id}/runs`, {
        method: 'POST',
        body: JSON.stringify({ idempotency_key: crypto.randomUUID().replaceAll('-', '') }),
      })
      navigate(`executions/${next.id}`)
    }, 'Nova solicitação criada; aprovação anterior não é reutilizada.')
  return (
    <>
      <a href="#executions" className="back-link">
        <ArrowLeft size={15} />
        Todas as execuções
      </a>
      <PageHeading
        eyebrow={`EXECUÇÃO ${r.id.slice(0, 8).toUpperCase()} · DADOS SINTÉTICOS`}
        title={r.campaign_name}
        description={r.objective}
        action={<Badge value={r.state} />}
      />
      {r.schedule_id && (
        <div className="notice">
          <Clock3 size={18} />
          <span>
            Execução automática autorizada.{' '}
            <Go to={`schedules/${r.schedule_id}`}>Plano de origem</Go> · autorização{' '}
            {r.approval?.schedule_authorization_id?.slice(0, 8)} · ocorrência{' '}
            {r.schedule_occurrence?.id.slice(0, 8)}.
          </span>
        </div>
      )}
      <div className="execution-toolbar">
        {user.role === 'administrator' && pending && !r.approval && (
          <button className="button primary" disabled={busy} onClick={() => setReview(true)}>
            <ShieldCheck size={17} />
            Revisar e aprovar
          </button>
        )}
        {user.role !== 'viewer' && pending && r.approval && (
          <button
            className="button primary"
            disabled={busy}
            onClick={() =>
              void run(
                () =>
                  api(`/executions/${id}/start`, {
                    method: 'POST',
                    body: JSON.stringify({ confirm: true }),
                  }),
                'Execução enviada ao worker.',
              )
            }
          >
            <Play size={17} />
            Confirmar e iniciar
          </button>
        )}
        {user.role !== 'viewer' && active && (
          <button
            className="button"
            disabled={busy}
            onClick={() =>
              void run(
                () => api(`/executions/${id}/cancel`, { method: 'POST' }),
                'Cancelamento solicitado; acompanhe o cleanup.',
              )
            }
          >
            <Square size={15} />
            Cancelar execução
          </button>
        )}
        {user.role === 'administrator' && pending && (
          <button
            className="button quiet"
            disabled={busy}
            onClick={() =>
              void run(
                () => api(`/executions/${id}/reject`, { method: 'POST' }),
                'Solicitação rejeitada.',
              )
            }
          >
            <XCircle size={16} />
            Rejeitar
          </button>
        )}
        {user.role !== 'viewer' && !active && (
          <button className="button" disabled={busy} onClick={() => void repeat()}>
            <Repeat2 size={16} />
            Repetir campanha
          </button>
        )}
        <button
          className="button"
          disabled={busy}
          onClick={() => void run(() => downloadReport(id, 'html'), 'Relatório HTML exportado.')}
        >
          <Download size={16} />
          Exportar HTML
        </button>
        <button
          className="button quiet"
          disabled={busy}
          onClick={() => void run(() => downloadReport(id, 'json'), 'Relatório JSON exportado.')}
        >
          <FileJson size={16} />
          JSON
        </button>
      </div>
      {r.error && (
        <div className="notice danger" role="alert">
          {r.error}
        </div>
      )}
      {pending && (
        <div className="notice">
          <ShieldCheck size={19} />
          {r.approval
            ? `Aprovação registrada até ${date(r.approval.expires_at)}. Duração máxima: ${r.approval.max_duration_seconds}s. Confirme para consumir a autorização de uso único.`
            : 'Aguardando revisão explícita do escopo por um administrador. Nenhum teste foi iniciado.'}
        </div>
      )}
      <div className="run-meta">
        <div>
          <small>AMBIENTE</small>
          <strong>Demo Lab · v{r.scope.environment_version}</strong>
        </div>
        <div>
          <small>SOLICITAÇÃO</small>
          <strong>{date(r.created_at)}</strong>
        </div>
        <div>
          <small>INÍCIO</small>
          <strong>{date(r.started_at)}</strong>
        </div>
        <div>
          <small>CONCLUSÃO</small>
          <strong>{date(r.ended_at)}</strong>
        </div>
      </div>
      <Panel
        title="Resultados e evidências"
        subtitle="Abra os eventos para inspecionar origem, regra, conteúdo original e hash."
      >
        <div className="execution-results">
          {r.executions.map((e) => (
            <article className="result-card" key={e.id}>
              <div className="result-title">
                <div>
                  <strong>
                    {r.scope.test_definitions.find((t) => t.id === e.test_id)?.name ?? e.test_id}
                  </strong>
                  <small>
                    {e.test_id} · marcador {e.marker}
                  </small>
                </div>
                <Badge value={e.result?.outcome ?? e.state} />
              </div>
              <p>{e.result?.reason ?? 'Sem classificação; aguardando execução e coleta.'}</p>
              {e.result && (
                <div className="result-flags">
                  <span>Execução confirmada: {e.executed ? 'sim' : 'não'}</span>
                  <span>Coleta completa: {e.result.collection_complete ? 'sim' : 'não'}</span>
                  <span>Lógica: {e.result.logic_version}</span>
                </div>
              )}
              <div className="evidence-list">
                {e.events.map((ev) => (
                  <button key={ev.id} className="evidence-button" onClick={() => setEvent(ev)}>
                    <FileJson size={16} />
                    <span>
                      {ev.kind === 'alert' ? 'Alerta' : 'Telemetria'} · {ev.source}
                    </span>
                    {e.evidence.some((x) => x.event_id === ev.id) && (
                      <span className="correlated">
                        <CheckCircle2 size={13} />
                        Correlacionado
                      </span>
                    )}
                    <ArrowRight size={15} />
                  </button>
                ))}
              </div>
            </article>
          ))}
        </div>
      </Panel>
      <Panel title="Trilha da execução" subtitle="Transições validadas e persistidas pelo backend.">
        <div className="timeline">
          {r.steps
            .filter((s) => !s.execution_id)
            .map((s) => (
              <div key={s.id}>
                <span className="timeline-dot" />
                <div>
                  <Badge value={s.state} />
                  <p>{s.message}</p>
                </div>
                <time>{date(s.created_at)}</time>
              </div>
            ))}
        </div>
      </Panel>
      <details className="scope-details">
        <summary>Inspecionar escopo e fingerprint de aprovação</summary>
        <p className="mono">SHA-256 · {r.scope_hash}</p>
        <pre>{JSON.stringify(r.scope, null, 2)}</pre>
      </details>
      {review && <ApprovalReview detail={r} onClose={() => setReview(false)} />}{' '}
      {event && (
        <Modal title="Evidência sintética" onClose={() => setEvent(null)}>
          <dl>
            <dt>Identificador original</dt>
            <dd className="mono">{event.source_id}</dd>
            <dt>Origem / regra</dt>
            <dd>
              {event.source} · {event.rule_id ?? 'Sem regra'}
            </dd>
            <dt>Timestamp</dt>
            <dd>{event.timestamp}</dd>
            <dt>SHA-256 do payload</dt>
            <dd className="mono">{event.sha256}</dd>
          </dl>
          <div className="notice">
            Dado sintético. Hash de integridade não equivale a assinatura digital.
          </div>
          <pre>{JSON.stringify(event.raw, null, 2)}</pre>
        </Modal>
      )}
    </>
  )
}

function ApprovalReview({ detail: r, onClose }: { detail: RunDetail; onClose: () => void }) {
  const [confirmed, setConfirmed] = useState(false),
    [duration, setDuration] = useState(60),
    { busy, run } = useAction()
  return (
    <Modal title="Revisar escopo de autorização" onClose={onClose}>
      <p>Autorização de uso único, válida por 15 minutos, exclusivamente para esta solicitação.</p>
      <div className="notice">
        Demo Lab · ambiente v{r.scope.environment_version} · {r.scope.test_definitions.length}{' '}
        testes sintéticos · sem acesso a endpoints externos.
      </div>
      <ul className="scope-list">
        {r.scope.test_definitions.map((t) => (
          <li key={t.id}>
            <CheckCircle2 size={15} />
            {t.name}
            <small>
              {t.technique_id ?? 'Sem ATT&CK'} · v{t.version}
            </small>
          </li>
        ))}
      </ul>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void run(async () => {
            await api(`/executions/${r.id}/approve`, {
              method: 'POST',
              body: JSON.stringify({
                confirm_scope_hash: r.scope_hash,
                max_duration_seconds: duration,
                validity_minutes: 15,
              }),
            })
            onClose()
          }, 'Escopo aprovado. O início exige confirmação separada.')
        }}
      >
        <label>
          Duração máxima (segundos)
          <input
            type="number"
            min={10}
            max={300}
            required
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
          />
        </label>
        <p className="fingerprint">
          Fingerprint SHA-256: <code>{r.scope_hash}</code>
        </p>
        <label className="checkbox-label">
          <input
            type="checkbox"
            required
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>
            Revisei e autorizo este escopo demonstrativo. Entendo que os resultados são sintéticos.
          </span>
        </label>
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Voltar
          </button>
          <Submit busy={busy}>Aprovar escopo</Submit>
        </div>
      </form>
    </Modal>
  )
}

export function CoveragePage() {
  const data = useData<Coverage>('/coverage', 5000),
    runs = useData<Page<Run>>('/executions?state=COMPLETED&limit=1000'),
    [before, setBefore] = useState(''),
    [after, setAfter] = useState(''),
    [comparison, setComparison] = useState<Comparison | null>(null),
    { busy, run } = useAction()
  if (data.isLoading) return <Loading />
  if (data.error) return <Failure error={data.error} />
  const c = data.data!
  return (
    <>
      <PageHeading
        eyebrow="OBSERVAR. DETECTAR. MELHORAR."
        title="Cobertura de detecção"
        description="Avalie resultados com denominadores explícitos e compare execuções reproduzíveis."
      />
      <div className="stats-grid">
        <div className="metric">
          <span>Técnicas catalogadas</span>
          <strong>{c.catalogued_techniques}</strong>
          <p>Snapshot oficial ATT&CK</p>
        </div>
        <div className="metric">
          <span>Técnicas avaliadas</span>
          <strong>{c.evaluated_techniques}</strong>
          <p>Em execuções concluídas</p>
        </div>
        <div className="metric metric-accent">
          <span>Detectados / testes válidos</span>
          <strong>
            {c.outcomes.DETECTED ?? 0} / {c.valid_tests}
          </strong>
          <p>{c.detected_percentage ?? '—'}% no escopo</p>
        </div>
        <div className="metric">
          <span>Inconclusivos</span>
          <strong>{c.outcomes.INCONCLUSIVE ?? 0}</strong>
          <p>Excluídos da taxa de detecção</p>
        </div>
      </div>
      <div className="notice">
        <ShieldCheck size={19} />
        <div>
          {c.scope}
          <p>
            {c.denominator}. {c.limitation}
          </p>
        </div>
      </div>
      <Panel
        title="Comparação entre execuções"
        subtitle="Escolha duas execuções da mesma campanha; diferenças de configuração são explicitadas."
      >
        <form
          className="comparison-form"
          onSubmit={(e) => {
            e.preventDefault()
            void run(
              async () =>
                setComparison(
                  await api<Comparison>(`/coverage/compare?before=${before}&after=${after}`),
                ),
              'Comparação carregada.',
            )
          }}
        >
          <label>
            Execução anterior
            <select
              required
              value={before}
              onChange={(e) => {
                setBefore(e.target.value)
                setComparison(null)
              }}
            >
              <option value="">Selecione uma execução</option>
              {runs.data?.items.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.id.slice(0, 8)} · {date(r.created_at)}
                </option>
              ))}
            </select>
          </label>
          <ArrowRight size={20} />
          <label>
            Execução atual
            <select
              required
              value={after}
              onChange={(e) => {
                setAfter(e.target.value)
                setComparison(null)
              }}
            >
              <option value="">Selecione uma execução</option>
              {runs.data?.items
                .filter((r) => r.id !== before)
                .map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.id.slice(0, 8)} · {date(r.created_at)}
                  </option>
                ))}
            </select>
          </label>
          <button
            className="button primary"
            disabled={busy || !before || !after || before === after}
          >
            Comparar execuções
          </button>
        </form>
        {comparison && (
          <>
            <div className={`notice ${comparison.comparable ? '' : 'warning'}`}>
              {comparison.comparable
                ? 'Configurações equivalentes; comparação do mesmo escopo.'
                : 'Configurações diferentes ou resultados parciais. Revise as diferenças antes de concluir melhoria ou regressão.'}
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Teste</th>
                    <th>Anterior</th>
                    <th>Atual</th>
                    <th>Mudança</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.tests.map((t) => (
                    <tr key={t.test_id}>
                      <td>{t.test_id}</td>
                      <td>
                        <Badge value={t.before} />
                      </td>
                      <td>
                        <Badge value={t.after} />
                      </td>
                      <td>{t.changed ? 'Resultado alterado' : 'Sem alteração'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <details className="scope-details">
              <summary>Inspecionar configurações, regras e ambiente</summary>
              <pre>
                {JSON.stringify(
                  { antes: comparison.before_scope, depois: comparison.after_scope },
                  null,
                  2,
                )}
              </pre>
            </details>
          </>
        )}
      </Panel>
      <Panel
        title="Lacunas observadas"
        subtitle="As categorias indicam evidências disponíveis; não comprovam risco de negócio."
      >
        <div className="gap-grid">
          {['OBSERVED_NOT_ALERTED', 'NO_TELEMETRY', 'INCONCLUSIVE'].map((s) => (
            <div key={s}>
              <Badge value={s} />
              <strong>{c.outcomes[s] ?? 0}</strong>
              <p>
                {s === 'OBSERVED_NOT_ALERTED'
                  ? 'Revisar a regra esperada e repetir o escopo após mudanças aprovadas.'
                  : s === 'NO_TELEMETRY'
                    ? 'Verificar instrumentação e disponibilidade da coleta antes de avaliar a detecção.'
                    : 'Restabelecer a fonte de dados e repetir a coleta para obter uma conclusão confiável.'}
              </p>
            </div>
          ))}
        </div>
      </Panel>
    </>
  )
}

export function Reports() {
  const data = useData<Page<Run>>('/reports?limit=1000'),
    campaigns = useData<Page<Campaign>>('/campaigns?limit=1000'),
    { busy, run } = useAction()
  return (
    <>
      <PageHeading
        eyebrow="EVIDÊNCIAS QUE PODEM SER INSPECIONADAS"
        title="Relatórios"
        description="Exporte resultados, escopo, aprovação, eventos e limitações em HTML ou JSON."
      />
      <Panel
        title="Execuções concluídas"
        subtitle="O relatório inclui resumo executivo e detalhamento técnico."
      >
        {data.isLoading ? (
          <Loading />
        ) : data.error ? (
          <Failure error={data.error} />
        ) : data.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Campanha</th>
                  <th>Execução</th>
                  <th>Data</th>
                  <th>Exportar</th>
                </tr>
              </thead>
              <tbody>
                {data.data.items.map((r) => (
                  <tr key={r.id}>
                    <td className="table-title">
                      {campaigns.data?.items.find((c) => c.id === r.campaign_id)?.name ??
                        r.campaign_id}
                      <small>Dados sintéticos</small>
                    </td>
                    <td>
                      <Go to={`executions/${r.id}`}>{r.id.slice(0, 8)}</Go>
                    </td>
                    <td>{date(r.ended_at)}</td>
                    <td>
                      <div className="inline-actions">
                        <button
                          className="button small"
                          disabled={busy}
                          onClick={() =>
                            void run(() => downloadReport(r.id, 'html'), 'HTML exportado.')
                          }
                        >
                          <Download size={14} />
                          HTML
                        </button>
                        <button
                          className="button small"
                          disabled={busy}
                          onClick={() =>
                            void run(() => downloadReport(r.id, 'json'), 'JSON exportado.')
                          }
                        >
                          <FileJson size={14} />
                          JSON
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhum relatório disponível">
            Os relatórios ficam disponíveis após a conclusão de uma campanha.
          </Empty>
        )}
      </Panel>
      <div className="notice">
        <Clock3 size={18} />
        PDF faz parte do roadmap. Agendamentos Demo preservam a autorização de origem. Nenhum
        relatório demonstra proteção de um ambiente real no Demo Mode.
      </div>
    </>
  )
}
