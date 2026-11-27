import { lazy, Suspense } from 'react'
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  CircleDot,
  FlaskConical,
  Grid2X2,
  Plus,
  Radio,
  ShieldCheck,
  Target,
} from 'lucide-react'
import {
  Badge,
  date,
  Empty,
  Failure,
  Go,
  Loading,
  navigate,
  PageHeading,
  Panel,
  useData,
} from './lib'
import type { Campaign, Connectors, Coverage, Page, Run, User } from './types'
const TrendChart = lazy(() => import('./TrendChart'))

export default function Overview({ user }: { user: User }) {
  const coverage = useData<Coverage>('/coverage', 5000),
    runs = useData<Page<Run>>('/executions?mode=demo&limit=6', 3000),
    campaigns = useData<Page<Campaign>>('/campaigns?limit=1000'),
    connectors = useData<Connectors>('/connectors', 5000)
  if (coverage.isLoading) return <Loading />
  if (coverage.error) return <Failure error={coverage.error} />
  const c = coverage.data!
  return (
    <>
      <PageHeading
        eyebrow="CENTRO DE OPERAÇÕES"
        title="Visão geral"
        description="Escopo Demo · simulações e evidências sintéticas, com indicadores separados do Linux real."
        action={
          user.role !== 'viewer' && (
            <button className="button primary" onClick={() => navigate('campaigns/new')}>
              <Plus size={17} />
              Nova campanha
            </button>
          )
        }
      />
      <div className="overview-banner">
        <div className="banner-icon">
          <FlaskConical size={24} />
        </div>
        <div>
          <strong>
            Demo Lab <span className="subtle-tag">DADOS SINTÉTICOS</span>
          </strong>
          <p>
            Explore o ciclo de validação. Os resultados deste painel não representam detecções
            reais.
          </p>
        </div>
        <a href="#tests">
          Explorar testes <ArrowUpRight size={17} />
        </a>
      </div>
      <div className="stats-grid">
        <Metric
          label="Técnicas avaliadas nesta release"
          value={c.evaluated_techniques ?? '—'}
          icon={<Grid2X2 size={18} />}
          detail={
            c.catalogued_techniques === null
              ? 'Catálogo atual indisponível'
              : `de ${c.catalogued_techniques} técnicas ativas no catálogo atual`
          }
        />
        <Metric
          label="Execuções solicitadas"
          value={c.total_runs}
          icon={<Activity size={18} />}
          detail={`${c.completed_tests} testes concluídos`}
        />
        <Metric
          label="Simulações detectadas"
          value={c.outcomes.DETECTED ?? 0}
          icon={<ShieldCheck size={18} />}
          detail={`${c.valid_tests} testes válidos no escopo`}
        />
        <Metric
          label="Taxa de detecção no escopo"
          value={c.detected_percentage === null ? '—' : `${c.detected_percentage}%`}
          icon={<Target size={18} />}
          detail="Dados sintéticos · denominador explícito"
        />
      </div>
      <div className="dashboard-grid">
        <Panel
          title="Evolução das detecções"
          subtitle="Resultados por execução concluída · dados sintéticos"
          action={<Go to="coverage">Ver cobertura</Go>}
        >
          <div className="chart-legend">
            <span>
              <i className="legend-dot detection" />
              Detectados
            </span>
            <span>
              <i className="legend-dot muted" />
              Avaliados
            </span>
          </div>
          {c.trend.length ? (
            <Suspense fallback={<Loading />}>
              <TrendChart trend={c.trend} />
            </Suspense>
          ) : (
            <Empty title="A evolução começa na primeira campanha">
              Conclua uma execução para visualizar a tendência de detecção.
            </Empty>
          )}
        </Panel>
        <Panel title="Resultados de validação" subtitle="Distribuição dos testes concluídos">
          <OutcomeSummary outcomes={c.outcomes} />
          <div className="panel-footnote">
            Somente testes concluídos. Ausência de alerta não comprova falha de detecção.
          </div>
        </Panel>
      </div>
      <Panel
        title="Últimas execuções"
        subtitle="Histórico rastreável de validação"
        action={<Go to="executions">Ver todas</Go>}
      >
        {runs.error ? (
          <Failure error={runs.error} />
        ) : runs.isLoading ? (
          <Loading />
        ) : runs.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Campanha / execução</th>
                  <th>Modo</th>
                  <th>Estado</th>
                  <th>Solicitada em</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {runs.data.items.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <a href={`#executions/${r.id}`} className="table-title">
                        {campaigns.data?.items.find((x) => x.id === r.campaign_id)?.name ??
                          'Campanha'}
                        <small>{r.id.slice(0, 8)}</small>
                      </a>
                    </td>
                    <td>
                      <span className="subtle-tag">Demo Lab</span>
                    </td>
                    <td>
                      <Badge value={r.state} />
                    </td>
                    <td className="muted-text">{date(r.created_at)}</td>
                    <td>
                      <Go to={`executions/${r.id}`}>Detalhes</Go>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma execução por aqui">
            Crie uma campanha, revise o escopo e autorize sua primeira simulação.
          </Empty>
        )}
      </Panel>
      <div className="dashboard-grid lower">
        <Panel title="Saúde das integrações" subtitle="Estado real dos componentes configurados">
          {connectors.error ? (
            <Failure error={connectors.error} />
          ) : connectors.isLoading ? (
            <Loading />
          ) : (
            <div className="connector-list">
              {connectors.data?.items.map((x) => (
                <div key={x.id}>
                  <span className="connector-icon">
                    {x.id === 'demo' ? <FlaskConical size={20} /> : <Radio size={20} />}
                  </span>
                  <div>
                    <strong>{x.name}</strong>
                    <small>{x.description}</small>
                  </div>
                  <Badge value={x.status} />
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title="Worker de execução" subtitle="Fila durável no PostgreSQL">
          {connectors.error ? (
            <Failure error={connectors.error} />
          ) : connectors.isLoading ? (
            <Loading />
          ) : (
            <div className="worker-info">
              <span className={`worker-orb ${connectors.data?.worker_online ? 'online' : ''}`}>
                <Activity size={23} />
              </span>
              <div>
                <strong>
                  {connectors.data?.worker_online
                    ? 'Worker disponível'
                    : 'Worker sem heartbeat recente'}
                </strong>
                <p>
                  {connectors.data?.worker_online
                    ? 'Aguardando campanhas autorizadas.'
                    : 'Execuções permanecem na fila até o worker iniciar.'}
                </p>
              </div>
            </div>
          )}
          <div className="panel-footnote">
            Agendamentos Demo exigem aprovação administrativa com validade e limites. Linux real
            exige configuração opt-in e aprovação por outra pessoa.
          </div>
        </Panel>
      </div>
      <Panel
        title="Seu próximo passo"
        subtitle="Um fluxo, da hipótese à evidência"
        className="workflow-panel"
      >
        <div className="workflow-steps">
          {[
            {
              to: 'tests',
              number: '01',
              icon: BookOpen,
              title: 'Escolha o comportamento',
              text: 'Consulte os testes e seus pré-requisitos.',
            },
            {
              to: 'campaigns',
              number: '02',
              icon: Target,
              title: 'Defina uma campanha',
              text: 'Revise o laboratório, os ativos e o escopo.',
            },
            {
              to: 'reports',
              number: '03',
              icon: ShieldCheck,
              title: 'Examine as evidências',
              text: 'Conecte resultados a observações registradas.',
            },
          ].map((step) => (
            <a key={step.number} href={`#${step.to}`}>
              <span className="step-number">{step.number}</span>
              <step.icon size={20} />
              <strong>{step.title}</strong>
              <p>{step.text}</p>
              <ArrowRight size={16} />
            </a>
          ))}
        </div>
      </Panel>
      <p className="scope-note">
        <CircleDot size={14} />
        {c.denominator}. {c.limitation}
      </p>
    </>
  )
}

const outcomeColors: Record<string, string> = {
  DETECTED: 'var(--detection)',
  OBSERVED_NOT_ALERTED: 'var(--warning)',
  NO_TELEMETRY: 'var(--defensive)',
  INCONCLUSIVE: 'var(--purple)',
  EXECUTION_FAILED: 'var(--offensive)',
}

export function OutcomeSummary({ outcomes }: { outcomes: Record<string, number> }) {
  const keys = [...new Set([...Object.keys(outcomeColors).slice(0, 4), ...Object.keys(outcomes)])]
  const total = keys.reduce((sum, key) => sum + (outcomes[key] ?? 0), 0)
  let cursor = 0
  const stops = keys.map((key) => {
    const start = cursor
    cursor += total ? ((outcomes[key] ?? 0) / total) * 100 : 0
    return `${outcomeColors[key] ?? 'var(--frost)'} ${start}% ${cursor}%`
  })
  return (
    <>
      <div className="outcome-summary">
        <div
          className="outcome-ring"
          aria-hidden="true"
          style={{ background: total ? `conic-gradient(${stops.join(',')})` : 'var(--steel)' }}
        >
          <div>
            <strong>{total}</strong>
            <span>concluídos</span>
          </div>
        </div>
        <p>
          Resultados no escopo<strong>Demo Lab</strong>
          <span>Simulação sintética</span>
        </p>
      </div>
      <div className="outcome-list">
        {keys
          .filter((key) => key !== 'EXECUTION_FAILED' || outcomes[key])
          .map((key) => (
            <div key={key}>
              <Badge value={key} />
              <strong>{outcomes[key] ?? 0}</strong>
            </div>
          ))}
      </div>
    </>
  )
}

function Metric({
  label,
  value,
  icon,
  detail,
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  detail: string
}) {
  return (
    <div className="metric">
      <div>
        <span>{label}</span>
        {icon}
      </div>
      <strong>{value}</strong>
      <p>{detail}</p>
    </div>
  )
}
