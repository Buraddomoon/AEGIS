import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, date, Empty, Failure, Loading, Modal, Panel, useData } from './lib'
import type { Page, User } from './types'

type ReviewStatus = 'pending' | 'reviewed' | 'rejected'
interface Source {
  document_id: string
  source_commit: string
  source_sha256: string
  source_path: string
  source_url: string
  provenance: 'operator_supplied'
  imported_at: string
  imported_by: string
}
interface Entry {
  id: string
  guid: string
  name: string
  technique_id: string
  platforms: string[]
  attack_mapping_status: string
  source: Source
  review_status: ReviewStatus
  review_sequence: number
  executable: false
  approved: false
  available_for_new_scope: false
}
interface Review {
  id: string
  sequence: number
  decision: ReviewStatus
  note: string
  created_at: string
  reviewed_by: string
}
interface Detail extends Entry {
  description: string
  dependencies: { description: string; has_prereq: boolean; has_setup: boolean }[]
  dependency_executor: string
  input_arguments: Record<string, { type: string; description: string; has_default: boolean }>
  executor: string
  has_cleanup: boolean
  elevation_required: boolean
  latest_review: Review | null
}
const reviewLabels = {
  pending: 'Pendente de revisão',
  reviewed: 'Metadado revisado',
  rejected: 'Metadado rejeitado',
}
const mappingLabels: Record<string, string> = {
  active: 'Ativa no catálogo ATT&CK',
  revoked: 'Revogada',
  deprecated: 'Descontinuada',
  absent: 'Ausente da release atual',
  unknown: 'Associação não encontrada no catálogo ATT&CK local',
}
const limitation =
  'Somente metadados · execução desabilitada. Revisar não autoriza campanhas, instalação ou downloads. Risco operacional não avaliado.'

export function AtomicCatalog({ user }: { user: User }) {
  const [query, setQuery] = useState(''),
    [platform, setPlatform] = useState(''),
    [review, setReview] = useState(''),
    [filters, setFilters] = useState(''),
    [offset, setOffset] = useState(0),
    [selected, setSelected] = useState<string | null>(null),
    [importing, setImporting] = useState(false)
  const path = `/catalog/atomic?limit=20&offset=${offset}${filters}`,
    data = useData<Page<Entry>>(path)
  return (
    <>
      <Panel
        title="Catálogo Atomic versionado"
        subtitle={limitation}
        action={
          user.role === 'administrator' && (
            <button className="button primary" onClick={() => setImporting(true)}>
              Importar metadados Atomic
            </button>
          )
        }
      >
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault()
            setSelected(null)
            setOffset(0)
            setFilters(
              `&q=${encodeURIComponent(query)}&platform=${encodeURIComponent(platform)}&review_status=${review}`,
            )
          }}
        >
          <label>
            Pesquisar Atomic
            <input
              aria-label="Pesquisar Atomic"
              maxLength={100}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Nome, GUID, técnica ou commit"
            />
          </label>
          <label>
            Plataforma Atomic
            <input
              aria-label="Plataforma Atomic"
              maxLength={40}
              value={platform}
              onChange={(e) => setPlatform(e.target.value)}
              placeholder="linux, macos, windows…"
            />
          </label>
          <label>
            Revisão
            <select
              aria-label="Revisão Atomic"
              value={review}
              onChange={(e) => setReview(e.target.value)}
            >
              <option value="">Todas</option>
              {Object.entries(reviewLabels).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <button className="button" type="submit">
            Filtrar Atomic
          </button>
          <button
            className="button"
            type="button"
            onClick={() => {
              setSelected(null)
              void data.refetch()
            }}
          >
            Atualizar catálogo Atomic
          </button>
        </form>
        {data.isLoading ? (
          <Loading />
        ) : data.error ? (
          <Failure error={data.error} />
        ) : (
          <>
            <p>{data.data!.total} metadados · todas as versões importadas</p>
            {!data.data!.items.length ? (
              <Empty title="Nenhum metadado Atomic encontrado">
                Importe um YAML revisado ou ajuste os filtros. O catálogo não baixa testes
                automaticamente.
              </Empty>
            ) : (
              <div className="test-grid">
                {data.data!.items.map((entry) => (
                  <Panel key={entry.id} className="test-card">
                    <h3>{entry.name}</h3>
                    <p>
                      {entry.technique_id} · {entry.platforms.join(', ')}
                    </p>
                    <p>{reviewLabels[entry.review_status]} · Não executável</p>
                    <p>
                      Commit <code>{entry.source.source_commit}</code>
                    </p>
                    <button className="button" onClick={() => setSelected(entry.id)}>
                      Inspecionar {entry.name}
                    </button>
                  </Panel>
                ))}
              </div>
            )}
            <div className="toolbar">
              <button
                className="button"
                disabled={offset === 0}
                onClick={() => {
                  setSelected(null)
                  setOffset(Math.max(0, offset - 20))
                }}
              >
                Página Atomic anterior
              </button>
              <span>Página {Math.floor(offset / 20) + 1}</span>
              <button
                className="button"
                disabled={offset + 20 >= data.data!.total}
                onClick={() => {
                  setSelected(null)
                  setOffset(offset + 20)
                }}
              >
                Próxima página Atomic
              </button>
            </div>
          </>
        )}
      </Panel>
      {selected && !data.error && (
        <AtomicDetail key={selected} id={selected} user={user} onClose={() => setSelected(null)} />
      )}
      {importing && <AtomicImport onClose={() => setImporting(false)} />}
    </>
  )
}

function AtomicImport({ onClose }: { onClose: () => void }) {
  const [commit, setCommit] = useState(''),
    [sha, setSha] = useState(''),
    [content, setContent] = useState(''),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<Error | null>(null),
    cache = useQueryClient()
  return (
    <Modal title="Importar metadados Atomic" onClose={onClose}>
      <p>
        Um arquivo YAML UTF-8 de até 64 KiB, até 100 testes. Commit e SHA256 são declarações do
        operador; a autenticidade upstream não é verificada. Nenhum código será instalado ou
        executado.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setError(null)
          setBusy(true)
          try {
            if (new TextEncoder().encode(content).length > 65536)
              throw new Error('YAML excede 64 KiB UTF-8.')
            await api('/catalog/atomic/imports', {
              method: 'POST',
              body: JSON.stringify({ source_commit: commit, source_sha256: sha, content }),
            })
            await cache.invalidateQueries()
            onClose()
          } catch (err) {
            setError(err instanceof Error ? err : new Error('Falha na importação.'))
          } finally {
            setBusy(false)
          }
        }}
      >
        <label>
          Commit oficial informado
          <input
            aria-label="Commit oficial informado"
            required
            pattern="[a-f0-9]{40}"
            maxLength={40}
            value={commit}
            onChange={(e) => setCommit(e.target.value)}
          />
        </label>
        <label>
          SHA256 do YAML
          <input
            aria-label="SHA256 do YAML"
            required
            pattern="[a-f0-9]{64}"
            maxLength={64}
            value={sha}
            onChange={(e) => setSha(e.target.value)}
          />
        </label>
        <label>
          YAML Atomic
          <textarea
            aria-label="YAML Atomic"
            required
            maxLength={65536}
            rows={12}
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
        </label>
        {error && <Failure error={error} />}
        <button className="button primary" disabled={busy} type="submit">
          {busy ? 'Importando…' : 'Importar somente metadados'}
        </button>
      </form>
    </Modal>
  )
}

function AtomicDetail({ id, user, onClose }: { id: string; user: User; onClose: () => void }) {
  const data = useData<Detail>(`/catalog/atomic/entries/${id}`),
    history = useData<Page<Review>>(`/catalog/atomic/entries/${id}/reviews?limit=20`),
    [note, setNote] = useState(''),
    [decision, setDecision] = useState('reviewed'),
    [busy, setBusy] = useState(false),
    [error, setError] = useState<Error | null>(null),
    cache = useQueryClient()
  const item = data.data
  return (
    <Modal title="Inspecionar metadado Atomic" onClose={onClose}>
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        item && (
          <>
            <h3>{item.name}</h3>
            <p className="notice">{limitation}</p>
            <p>{item.description}</p>
            <dl className="atomic-identifiers">
              <dt>GUID oficial</dt>
              <dd>{item.guid}</dd>
              <dt>Associação ATT&CK declarada</dt>
              <dd>
                {item.technique_id} ·{' '}
                {mappingLabels[item.attack_mapping_status] ?? 'Estado desconhecido'}
              </dd>
              <dt>Plataformas declaradas</dt>
              <dd>{item.platforms.join(', ')}</dd>
              <dt>Executor declarado</dt>
              <dd>{item.executor}</dd>
              <dt>Elevação declarada</dt>
              <dd>{item.elevation_required ? 'Sim' : 'Não'}</dd>
              <dt>Cleanup declarado</dt>
              <dd>
                {item.has_cleanup
                  ? 'Presente; eficácia não verificada'
                  : 'Ausente; limpeza não garantida'}
              </dd>
              <dt>Procedência</dt>
              <dd>Informada pelo operador · autenticidade upstream não verificada</dd>
              <dt>Commit</dt>
              <dd>{item.source.source_commit}</dd>
              <dt>SHA256 dos bytes</dt>
              <dd>{item.source.source_sha256}</dd>
              <dt>Caminho</dt>
              <dd>{item.source.source_path}</dd>
              <dt>Importado em</dt>
              <dd>{date(item.source.imported_at)}</dd>
            </dl>
            <h4>Inputs declarados</h4>
            {Object.entries(item.input_arguments).length ? (
              <ul>
                {Object.entries(item.input_arguments).map(([name, input]) => (
                  <li key={name}>
                    {name} ({input.type}): {input.description} ·{' '}
                    {input.has_default ? 'Default omitido' : 'Sem default'}
                  </li>
                ))}
              </ul>
            ) : (
              <p>Nenhum input declarado.</p>
            )}
            <h4>Dependências declaradas</h4>
            <p>
              Executor de dependências: {item.dependency_executor || 'Não declarado'}. Comandos e
              defaults são omitidos.
            </p>
            {item.dependencies.length ? (
              <ul>
                {item.dependencies.map((dep, index) => (
                  <li key={index}>
                    {dep.description} · Verificação: {dep.has_prereq ? 'declarada' : 'ausente'} ·
                    Setup: {dep.has_setup ? 'declarado' : 'ausente'}
                  </li>
                ))}
              </ul>
            ) : (
              <p>Nenhuma dependência declarada.</p>
            )}
            <h4>Revisão de metadados</h4>
            <p>{reviewLabels[item.review_status]}</p>
            {history.isLoading ? (
              <Loading />
            ) : history.error ? (
              <Failure error={history.error} />
            ) : (
              <>
                <p>
                  Últimas {history.data!.items.length} de {history.data!.total} revisões; decisões
                  anteriores são preservadas.
                </p>
                <ul>
                  {history.data!.items.map((row) => (
                    <li key={row.id}>
                      #{row.sequence} · {reviewLabels[row.decision]} · {date(row.created_at)} ·{' '}
                      {row.reviewed_by}: {row.note}
                    </li>
                  ))}
                </ul>
              </>
            )}
            {user.role === 'administrator' && (
              <form
                onSubmit={async (e) => {
                  e.preventDefault()
                  setBusy(true)
                  setError(null)
                  try {
                    await api(`/catalog/atomic/entries/${id}/reviews`, {
                      method: 'POST',
                      body: JSON.stringify({
                        decision,
                        note,
                        expected_sequence: item.review_sequence,
                      }),
                    })
                    setNote('')
                    await cache.invalidateQueries()
                  } catch (err) {
                    setError(err instanceof Error ? err : new Error('Falha na revisão.'))
                    await cache.invalidateQueries()
                  } finally {
                    setBusy(false)
                  }
                }}
              >
                <label>
                  Decisão sobre o metadado
                  <select
                    aria-label="Decisão sobre o metadado"
                    value={decision}
                    onChange={(e) => setDecision(e.target.value)}
                  >
                    <option value="reviewed">Metadado revisado</option>
                    <option value="rejected">Metadado rejeitado</option>
                  </select>
                </label>
                <label>
                  Justificativa da revisão
                  <textarea
                    aria-label="Justificativa da revisão"
                    required
                    maxLength={2000}
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                  />
                </label>
                {error && <Failure error={error} />}
                <button className="button primary" disabled={busy || !note.trim()} type="submit">
                  Registrar revisão de metadado
                </button>
              </form>
            )}
          </>
        )
      )}
    </Modal>
  )
}
