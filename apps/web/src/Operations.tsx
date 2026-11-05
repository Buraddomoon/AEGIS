import { useState } from 'react'
import { CoverageFilters, useCoverageFilters } from './CoverageFilters'
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
import type { Campaign, EventRecord, Lab, Page, Run, RunDetail, Test, User } from './types'

export function Campaigns({ user }: { user: User }) {
  const labs = useData<Page<Lab>>('/labs'),
    data = useData<Page<Campaign>>('/campaigns?limit=1000'),
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
                <span className="subtle-tag">
                  {labs.data?.items.find((l) => l.id === c.laboratory_id)?.kind === 'linux'
                    ? 'Linux real'
                    : 'Demo Lab'}
                </span>
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
          <select
            required
            value={lab}
            onChange={(e) => {
              setLab(e.target.value)
              setSelected([])
            }}
          >
            <option value="">Selecione o ambiente</option>
            {labs.data?.items
              .filter((l) => l.authorized)
              .map((l) => (
                <option value={l.id} key={l.id}>
                  {l.name} · versão {l.environment_version} · {l.synthetic ? 'sintético' : 'real'}
                </option>
              ))}
          </select>
        </label>
        <fieldset>
          <legend>Simulações do escopo</legend>
          {tests.data?.items
            .filter(
              (t) =>
                t.approved &&
                t.available_for_new_scope !== false &&
                t.execution_kind ===
                  (labs.data?.items.find((l) => l.id === lab)?.kind === 'linux'
                    ? 'linux_marker'
                    : 'demo'),
            )
            .map((t) => (
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
                  <small>
                    {t.technique_id ?? 'Sem associação ATT&CK'} ·{' '}
                    {t.execution_kind === 'demo' ? 'sintético' : 'efeito real em laboratório'}
                  </small>
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
    [mode, setMode] = useState(''),
    [page, setPage] = useState(0)
  const data = useData<Page<Run>>(
      `/executions?limit=25&offset=${page * 25}${mode ? `&mode=${mode}` : ''}${filter ? `&state=${filter}` : ''}${campaign ? `&campaign_id=${campaign}` : ''}`,
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
          aria-label="Modo de execução"
          value={mode}
          onChange={(e) => {
            setMode(e.target.value)
            setPage(0)
          }}
        >
          <option value="">Todos os modos</option>
          <option value="demo">Demo · sintético</option>
          <option value="linux">Linux real</option>
        </select>
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
                          <small>
                            {r.id.slice(0, 8)} · {r.synthetic ? 'sintético' : 'Linux real'}
                          </small>
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
        eyebrow={`EXECUÇÃO ${r.id.slice(0, 8).toUpperCase()} · ${r.synthetic ? 'DADOS SINTÉTICOS' : 'LINUX REAL'}`}
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
        {user.role === 'administrator' &&
          pending &&
          !r.approval &&
          (r.synthetic || user.id !== r.requested_by) && (
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
          onClick={() => void run(() => downloadReport(id, 'pdf'), 'Relatório PDF exportado.')}
        >
          <Download size={16} />
          Exportar PDF
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
      {!r.synthetic && (
        <div className="notice warning">
          Efeito real limitado ao marcador revisado. Aprovação exige administrador diferente do
          solicitante. Comprovante do executor não comprova detecção.{' '}
          {r.scope.telemetry?.provider === 'wazuh-indexer'
            ? 'Coleta Wazuh prevista no escopo; confira tentativas, janela e evidências.'
            : 'SIEM não consultado.'}
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
          <strong>
            {r.synthetic ? 'Demo Lab' : 'Linux real'} · v{r.scope.environment_version}
          </strong>
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
              {!e.synthetic && (
                <details className="scope-details">
                  <summary>
                    Comprovantes do executor e cleanup (não são evidência defensiva)
                  </summary>
                  <p>
                    Comprovantes do executor não são alertas. Hashes permitem inspecionar a
                    integridade dos registros.
                  </p>
                  <pre>
                    {JSON.stringify(
                      { receipt: e.runner_receipt, cleanup: e.runner_cleanup },
                      null,
                      2,
                    )}
                  </pre>
                </details>
              )}
              {e.collection && (
                <details className="scope-details">
                  <summary>Resumo da coleta · {e.collection.provider}</summary>
                  <p>
                    {e.collection.attempts} tentativa(s) · janela cumprida:{' '}
                    {e.collection.window_satisfied ? 'sim' : 'não'} · consulta completa:{' '}
                    {e.collection.complete ? 'sim' : 'não'}
                  </p>
                  <p>{e.collection.reason}</p>
                  <p>
                    {date(e.collection.started_at)} → {date(e.collection.ended_at)}
                  </p>
                </details>
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
        <Modal
          title={event.synthetic ? 'Evidência sintética' : 'Evidência defensiva'}
          onClose={() => setEvent(null)}
        >
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
            {event.synthetic ? 'Dado sintético. ' : ''}Hash de integridade não equivale a assinatura
            digital.
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
        {r.synthetic ? 'Demo Lab' : 'Linux real'} · ambiente v{r.scope.environment_version} ·{' '}
        {r.scope.test_definitions.length}{' '}
        {r.synthetic
          ? 'testes sintéticos · sem acesso a endpoints externos.'
          : 'marcador real em tmpfs · runner fixado · coleta conforme política revisada.'}
      </div>
      {!r.synthetic && (
        <div className="notice">
          {r.scope.telemetry?.provider === 'wazuh-indexer'
            ? `Wazuh somente leitura · agente ${r.scope.telemetry.policy?.agent_id} · regra esperada ${r.scope.telemetry.policy?.expected_rule} · espera de ingestão ${r.scope.telemetry.policy?.ingestion_wait_seconds}s. Este teste benigno avalia somente o pipeline de observação.`
            : 'Sem vínculo defensivo: resultado será inconclusivo quanto à detecção.'}
        </div>
      )}
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
                confirm_real_execution: !r.synthetic,
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
            {r.synthetic
              ? 'Revisei e autorizo este escopo demonstrativo. Entendo que os resultados são sintéticos.'
              : 'Revisei a identidade, isolamento e escopo. Autorizo o efeito real e a limpeza do marcador neste runner. Sou diferente do solicitante.'}
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

export { CoveragePage } from './CoveragePage'

export function Reports() {
  const filters = useCoverageFilters(),
    [page, setPage] = useState(0),
    data = useData<Page<Run>>(`/reports?${filters.query}&limit=100&offset=${page * 100}`),
    campaigns = useData<Page<Campaign>>('/campaigns?limit=1000'),
    { busy, run } = useAction()
  return (
    <>
      <PageHeading
        eyebrow="EVIDÊNCIAS QUE PODEM SER INSPECIONADAS"
        title="Relatórios"
        description="Exporte resultados, escopo, aprovação, eventos e limitações em PDF, HTML ou JSON."
      />
      <CoverageFilters
        filters={filters}
        busy={busy}
        onApply={() => setPage(0)}
        modeLabel="Modo dos relatórios"
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
                      <small>
                        {r.synthetic
                          ? 'Dados sintéticos'
                          : 'Linux real · fontes identificadas no relatório'}
                      </small>
                    </td>
                    <td>
                      <Go to={`executions/${r.id}`}>{r.id.slice(0, 8)}</Go>
                    </td>
                    <td>{date(r.ended_at)}</td>
                    <td>
                      <div className="inline-actions">
                        <button
                          className="button small"
                          disabled={busy || filters.dirty || data.isFetching}
                          onClick={() =>
                            void run(() => downloadReport(r.id, 'pdf'), 'PDF exportado.')
                          }
                        >
                          <Download size={14} />
                          PDF
                        </button>
                        <button
                          className="button small"
                          disabled={busy || filters.dirty || data.isFetching}
                          onClick={() =>
                            void run(() => downloadReport(r.id, 'html'), 'HTML exportado.')
                          }
                        >
                          <Download size={14} />
                          HTML
                        </button>
                        <button
                          className="button small"
                          disabled={busy || filters.dirty || data.isFetching}
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
      <div className="pagination">
        <button className="button" disabled={busy || page === 0} onClick={() => setPage(page - 1)}>
          Anterior
        </button>
        <span>
          Página {page + 1} · {data.data?.total ?? 0} relatórios no recorte
        </span>
        <button
          className="button"
          disabled={busy || (page + 1) * 100 >= (data.data?.total ?? 0)}
          onClick={() => setPage(page + 1)}
        >
          Próxima
        </button>
      </div>
      <div className="notice">
        <Go to="coverage">Exportar recorte agregado ou comparação entre execuções</Go>
      </div>
      <div className="notice">
        <Clock3 size={18} />
        PDF faz parte do roadmap. Agendamentos Demo preservam a autorização de origem. Nenhum
        relatório demonstra proteção de um ambiente real no Demo Mode.
      </div>
    </>
  )
}
