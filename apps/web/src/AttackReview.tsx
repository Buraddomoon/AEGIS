import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, Empty, Failure, Loading, Modal, Panel } from './lib'
import type { Page } from './types'

interface ReviewItem {
  plan_sha256: string
  candidate_id: string
  candidate_version: string
}
interface Change {
  id: string
  name: string
  kind: 'added' | 'changed' | 'absent'
  fields: string[]
  before: Record<string, unknown>
  after: Record<string, unknown>
}
interface Review extends ReviewItem {
  source_commit: string
  source_sha256: string
  license_sha256: string
  source_url: string
  provenance: string
  base_release_id: string
  database_scope: { host: string; port: number; database: string; schema: string }
  publication_status: 'not_applied' | 'already_applied'
  blockers: string[]
  counts: Record<string, number>
  reference_context?: {
    previous_format: string
    candidate_format: string
    objects: number
    relationships: number
  }
  changes: Page<Change>
  tests_requiring_review: Page<{
    id: string
    version: number
    technique_id: string
    approved: boolean
  }>
  test_reference_count: number
  authorization_policy: string
}
interface Instruction {
  plan_sha256: string
  candidate_id: string
  status: string
  command: string
  limitation: string
}
const base = '/catalog/attack/reviews'
const countLabels: Record<string, string> = {
  active: 'Técnicas ativas após publicação',
  added: 'Adições',
  changed: 'Alterações',
  absent: 'Fora da versão candidata',
  pending_runs: 'Execuções pendentes',
  reservations: 'Reservas de laboratório',
  resumable_schedules: 'Agendamentos retomáveis',
}
const blockerLabels: Record<string, string> = {
  projection_or_state_drift: 'Projeção ou estado diverge do histórico',
  license_review_required: 'Licença exige revisão no repositório',
  catalog_downgrade: 'Downgrade recusado',
  same_version_source_changed: 'Fonte da mesma versão foi alterada',
  immutable_version_conflict: 'Conflito com versão imutável',
  technique_identity_conflict: 'Conflito de identidade ATT&CK/STIX',
  execution_or_schedule_in_scope: 'Existem execuções, reservas ou agendamentos pendentes',
}

export function AttackReview() {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button className="button" onClick={() => setOpen(true)}>
        Revisar atualização ATT&CK
      </button>
      {open && <ReviewBrowser onClose={() => setOpen(false)} />}
    </>
  )
}

function ReviewBrowser({ onClose }: { onClose: () => void }) {
  const [selected, setSelected] = useState<string | null>(null),
    [page, setPage] = useState(0),
    [changePage, setChangePage] = useState(0),
    [testPage, setTestPage] = useState(0),
    [revision, setRevision] = useState(0)
  const listing = useQuery({
    queryKey: [base, page, revision],
    queryFn: () =>
      api<Page<ReviewItem> & { status: string }>(`${base}?offset=${page * 20}&limit=20`),
    retry: false,
    gcTime: 0,
  })
  return (
    <Modal title="Revisão administrativa ATT&CK" onClose={onClose}>
      <p>
        Planos preparados no host. Publicação exige o artefato exato e a credencial administrativa
        local. Nenhuma atualização é aplicada por esta tela.
      </p>
      <button
        className="button"
        onClick={() => {
          setSelected(null)
          setChangePage(0)
          setTestPage(0)
          setRevision((value) => value + 1)
        }}
      >
        Recarregar planos
      </button>
      {selected ? (
        <>
          <button className="button" onClick={() => setSelected(null)}>
            Voltar aos planos
          </button>
          <ReviewDetail
            key={`${selected}:${changePage}:${testPage}:${revision}`}
            identity={selected}
            changePage={changePage}
            testPage={testPage}
            onChangePage={setChangePage}
            onTestPage={setTestPage}
          />
        </>
      ) : listing.isFetching ? (
        <Loading />
      ) : listing.error ? (
        <Failure error={listing.error} />
      ) : listing.data?.status === 'disabled' ? (
        <Empty title="Revisão web desabilitada nesta implantação">
          A preparação e o planejamento permanecem disponíveis no host.
        </Empty>
      ) : (
        <>
          {listing.data?.items.map((item) => (
            <Panel key={item.plan_sha256}>
              <h3>Enterprise v{item.candidate_version}</h3>
              <p>Plano salvo · situação será revalidada ao abrir</p>
              <code className="review-hash">{item.plan_sha256}</code>
              <button
                className="button"
                onClick={() => {
                  setChangePage(0)
                  setTestPage(0)
                  setSelected(item.plan_sha256)
                }}
              >
                Inspecionar plano
              </button>
            </Panel>
          ))}
          {!listing.data?.items.length && (
            <Empty title="Nenhum plano preparado">
              Prepare e planeje um candidato oficial no host. Uma release nova não é presumida.
            </Empty>
          )}
          <Pagination
            label="planos"
            page={page}
            total={listing.data?.total ?? 0}
            onPage={setPage}
          />
        </>
      )}
    </Modal>
  )
}

function Pagination({
  label,
  page,
  total,
  onPage,
}: {
  label: string
  page: number
  total: number
  onPage: (page: number) => void
}) {
  return (
    <div className="pagination attack-review-pagination" aria-label={`Paginação de ${label}`}>
      <button className="button" disabled={!page} onClick={() => onPage(page - 1)}>
        Anterior · {label}
      </button>
      <span>
        Página {page + 1} · {total} registros
      </span>
      <button
        className="button"
        disabled={(page + 1) * 20 >= total}
        onClick={() => onPage(page + 1)}
      >
        Próxima · {label}
      </button>
    </div>
  )
}

function ReviewDetail({
  identity,
  changePage,
  testPage,
  onChangePage,
  onTestPage,
}: {
  identity: string
  changePage: number
  testPage: number
  onChangePage: (page: number) => void
  onTestPage: (page: number) => void
}) {
  const data = useQuery({
    queryKey: [base, identity, changePage, testPage],
    queryFn: () =>
      api<Review>(
        `${base}/${identity}?offset=${changePage * 20}&test_offset=${testPage * 20}&limit=20`,
      ),
    retry: false,
    gcTime: 0,
  })
  const [confirmed, setConfirmed] = useState(false),
    [busy, setBusy] = useState(false),
    [instruction, setInstruction] = useState<Instruction | null>(null),
    [error, setError] = useState<Error | null>(null),
    request = useRef(0)
  useEffect(() => {
    setConfirmed(false)
    setInstruction(null)
    setError(null)
    setBusy(false)
    return () => {
      request.current += 1
    }
  }, [data.dataUpdatedAt, data.isFetching])
  if (data.isFetching) return <Loading />
  if (data.error) return <Failure error={data.error} />
  const plan = data.data
  if (!plan || plan.plan_sha256 !== identity)
    return <Empty title="Identidade do plano divergente; recarregue" />
  const blocked = plan.blockers.length > 0 || plan.publication_status !== 'not_applied'
  async function validate() {
    const token = ++request.current
    setBusy(true)
    setInstruction(null)
    setError(null)
    try {
      const result = await api<Instruction>(`${base}/${identity}/instruction`, {
        cache: 'no-store',
      })
      if (token !== request.current) return
      if (
        result.plan_sha256 !== identity ||
        result.candidate_id !== plan!.candidate_id ||
        result.status !== 'host_only_not_applied'
      )
        throw new Error('Confirmação diverge do artefato revisado. Recarregue os planos.')
      setInstruction(result)
    } catch (reason) {
      if (token === request.current) {
        setError(reason as Error)
        setConfirmed(false)
      }
    } finally {
      if (token === request.current) setBusy(false)
    }
  }
  return (
    <section className="attack-review" aria-label="Plano ATT&CK revalidado">
      <h3>
        Enterprise v{plan.candidate_version} ·{' '}
        {plan.publication_status === 'already_applied' ? 'Já aplicado' : 'Ainda não aplicado'}
      </h3>
      <dl className="review-identifiers">
        {Object.entries({
          'SHA256 do plano': plan.plan_sha256,
          'Candidato exato': plan.candidate_id,
          'Release anterior': plan.base_release_id,
          Proveniência: plan.provenance,
          'Commit oficial': plan.source_commit,
          'SHA256 do bundle': plan.source_sha256,
          'SHA256 da licença': plan.license_sha256,
          Fonte: plan.source_url,
          'Destino revisado': `${plan.database_scope.host}:${plan.database_scope.port}/${plan.database_scope.database} · schema ${plan.database_scope.schema}`,
        }).map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>
              <code>{value}</code>
            </dd>
          </div>
        ))}
      </dl>
      <h4>Impacto e bloqueadores</h4>
      {plan.reference_context && (
        <p>
          Perfil de catálogo: {plan.reference_context.previous_format} →{' '}
          {plan.reference_context.candidate_format} · {plan.reference_context.objects} referências
          de contexto · {plan.reference_context.relationships} relações. Publicar uma nova release
          separa a cobertura atual do histórico, mesmo sem mudança nas técnicas.
        </p>
      )}
      <dl>
        {Object.entries(plan.counts).map(([key, value]) => (
          <div key={key}>
            <dt>{countLabels[key] ?? key}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <p>{plan.authorization_policy}</p>
      <p>
        Ausência significa fora da versão candidata; não implica revogação. Importar catálogo não
        comprova execução ou detecção.
      </p>
      {plan.blockers.map((blocker) => (
        <p className="notice warning" key={blocker}>
          {blockerLabels[blocker] ?? blocker}
        </p>
      ))}
      <h4>Diff de técnicas</h4>
      {plan.changes.items.map((change) => (
        <details key={change.id}>
          <summary>
            {change.id} · {change.name} ·{' '}
            {change.kind === 'absent'
              ? 'Fora da versão candidata'
              : change.kind === 'added'
                ? 'Adição'
                : 'Alteração'}
          </summary>
          {change.fields.map((field) => (
            <div key={field}>
              <h5>{field}</h5>
              <p>Antes</p>
              <pre>{JSON.stringify(change.before[field], null, 2)}</pre>
              <p>Depois</p>
              <pre>{JSON.stringify(change.after[field], null, 2)}</pre>
            </div>
          ))}
        </details>
      ))}
      {!plan.changes.total && <p>Nenhuma mudança na projeção de técnicas.</p>}
      <Pagination
        label="mudanças"
        page={changePage}
        total={plan.changes.total}
        onPage={onChangePage}
      />
      <h4>Testes afetados por retirada ou ausência</h4>
      <p>{plan.test_reference_count} referências de testes incluídas no hash do plano.</p>
      {plan.tests_requiring_review.items.map((test) => (
        <p key={test.id}>
          {test.id} v{test.version} · {test.technique_id} ·{' '}
          {test.approved
            ? 'Aprovado no cadastro; revisar disponibilidade'
            : 'Sem aprovação no cadastro'}
        </p>
      ))}
      {!plan.tests_requiring_review.total && (
        <p>Nenhum teste exige revisão por retirada ou ausência.</p>
      )}
      <Pagination
        label="testes"
        page={testPage}
        total={plan.tests_requiring_review.total}
        onPage={onTestPage}
      />
      <label>
        <input
          type="checkbox"
          checked={confirmed}
          disabled={blocked || busy || !!error}
          onChange={(e) => {
            setConfirmed(e.target.checked)
            setInstruction(null)
          }}
        />{' '}
        Revisei integralmente o destino, a licença, o diff e os impactos deste hash exato.
      </label>
      <button
        className="button primary"
        disabled={!confirmed || blocked || busy || !!error}
        onClick={() => void validate()}
      >
        {busy ? 'Revalidando…' : 'Validar instrução local'}
      </button>
      {error && <Failure error={error} />}
      {error && <p>Confirmação descartada. Recarregue e revise um plano vigente.</p>}
      {instruction && confirmed && (
        <div role="status">
          <p>Instrução validada · publicação ainda não aplicada por esta ação.</p>
          <pre>{instruction.command}</pre>
          <p>{instruction.limitation}</p>
        </div>
      )}
    </section>
  )
}
