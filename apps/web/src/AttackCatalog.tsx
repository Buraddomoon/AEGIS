import { useState } from 'react'
import { ExternalLink, History } from 'lucide-react'
import { api, date, Empty, Failure, Loading, Modal, Panel, useData } from './lib'
import type {
  CatalogLifecycle,
  CatalogReference,
  CatalogRelease,
  CatalogStatus,
  Page,
  Technique,
} from './types'

export const lifecycleLabels: Record<CatalogLifecycle, string> = {
  active: 'Ativa',
  revoked: 'Revogada',
  deprecated: 'Descontinuada',
  absent: 'Fora da versão atual',
}
export interface TechniquePage extends Page<Technique> {
  catalog: CatalogReference
  catalog_release_id: string
}

// A matrix spans pages; never combine results from different published releases.
export async function loadTechniques(mode: string, lifecycle: string): Promise<TechniquePage> {
  let first: TechniquePage | null = null
  const items: Technique[] = [],
    seen = new Set<string>()
  for (let page = 0; page < 100; page++) {
    const expected: string = first ? `&catalog_release_id=${first.catalog_release_id}` : ''
    const result: TechniquePage = await api<TechniquePage>(
      `/techniques?limit=1000&offset=${items.length}&mode=${mode}&lifecycle=${lifecycle}${expected}`,
    )
    if (
      !/^[a-f0-9]{64}$/.test(result.catalog_release_id ?? '') ||
      result.catalog?.release_id !== result.catalog_release_id ||
      !Array.isArray(result.items) ||
      !Number.isInteger(result.total) ||
      result.total < 0 ||
      result.total > 100_000
    ) {
      throw new Error('Metadados do catálogo indisponíveis ou incompatíveis.')
    }
    if (
      first &&
      (result.catalog_release_id !== first.catalog_release_id || result.total !== first.total)
    ) {
      throw new Error('Catálogo mudou durante a consulta. Recarregue os resultados.')
    }
    first ??= result
    for (const technique of result.items) {
      if (seen.has(technique.id)) throw new Error('Paginação do catálogo inconsistente.')
      seen.add(technique.id)
      items.push(technique)
    }
    if (items.length === first.total) return { ...first, items }
    if (!result.items.length || items.length > first.total)
      throw new Error('Catálogo recebido está incompleto.')
  }
  throw new Error('Catálogo excede o limite desta visualização.')
}

export function AttackCatalogStatus({
  expectedRelease,
  onRefresh,
}: {
  expectedRelease: string
  onRefresh: () => void
}) {
  const data = useData<CatalogStatus>('/catalog/attack'),
    [history, setHistory] = useState(false)
  if (data.isLoading) return <Loading />
  if (data.error) return <Failure error={data.error} />
  const current = data.data?.current,
    counts = data.data?.counts
  if (!current || !counts)
    return <div className="notice warning">Catálogo pendente de inicialização e revisão.</div>
  if (current.id !== expectedRelease)
    return (
      <div className="notice warning">
        O catálogo mudou.{' '}
        <button className="text-link" onClick={onRefresh}>
          Recarregar consulta
        </button>
      </div>
    )
  return (
    <>
      <Panel className="catalog-provenance">
        <div>
          <div className="eyebrow">CATÁLOGO VERSIONADO</div>
          <strong>Enterprise v{current.dataset_version}</strong>
          <p className="muted-text">
            {counts.active} ativas · {counts.revoked} revogadas · {counts.deprecated} descontinuadas
            · {counts.absent} fora da versão atual
          </p>
          <p className="muted-text">
            {current.provenance === 'official_commit'
              ? 'Fonte oficial fixada por commit'
              : 'Snapshot inicial distribuído · somente técnicas ativas · commit não registrado'}{' '}
            · registrado em {date(current.created_at)}
          </p>
          <details className="catalog-identifiers">
            <summary>Origem e integridade</summary>
            <dl>
              <dt>Release no ÆGIS</dt>
              <dd>
                <code>{current.id}</code>
              </dd>
              <dt>Commit da fonte</dt>
              <dd>
                <code>{current.source_commit ?? 'Não registrado no snapshot inicial'}</code>
              </dd>
              <dt>SHA256 do bundle</dt>
              <dd>
                <code>{current.source_sha256}</code>
              </dd>
              <dt>SHA256 da licença</dt>
              <dd>
                <code>{current.license_sha256}</code>
              </dd>
            </dl>
            <a className="text-link" href={current.source_url} target="_blank" rel="noreferrer">
              Fonte STIX oficial <ExternalLink size={14} />
            </a>
          </details>
        </div>
        <button className="button" onClick={() => setHistory(true)}>
          <History size={16} />
          Histórico do catálogo
        </button>
      </Panel>
      {history && <CatalogHistory onClose={() => setHistory(false)} />}
    </>
  )
}

function CatalogHistory({ onClose }: { onClose: () => void }) {
  const [page, setPage] = useState(0),
    [selected, setSelected] = useState<CatalogRelease | null>(null)
  const data = useData<Page<CatalogRelease>>(
    `/catalog/attack/releases?limit=20&offset=${page * 20}`,
  )
  return (
    <Modal title="Histórico do catálogo ATT&CK" onClose={onClose}>
      {selected ? (
        <>
          <button className="button" onClick={() => setSelected(null)}>
            Voltar às releases
          </button>
          <HistoricalSnapshot release={selected} />
        </>
      ) : data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        <>
          <p className="muted-text">
            Releases preservadas. Uma mudança de catálogo não reescreve escopos nem evidências
            anteriores.
          </p>
          {data.data?.items.map((release) => (
            <div className="catalog-history-row" key={release.id}>
              <div>
                <strong>Enterprise v{release.dataset_version}</strong>
                <p>
                  {release.provenance === 'official_commit'
                    ? 'Commit oficial fixado'
                    : 'Snapshot inicial'}{' '}
                  · {date(release.created_at)}
                </p>
                <code>{release.id.slice(0, 12)}</code>
              </div>
              <button className="button" onClick={() => setSelected(release)}>
                Inspecionar snapshot
              </button>
            </div>
          ))}
          {!data.data?.items.length && <Empty title="Nenhuma release registrada" />}
          <div className="pagination">
            <button className="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
              Anterior
            </button>
            <span>Página {page + 1}</span>
            <button
              className="button"
              disabled={(page + 1) * 20 >= (data.data?.total ?? 0)}
              onClick={() => setPage(page + 1)}
            >
              Próxima
            </button>
          </div>
        </>
      )}
    </Modal>
  )
}

function HistoricalSnapshot({ release }: { release: CatalogRelease }) {
  const [query, setQuery] = useState(''),
    [page, setPage] = useState(0)
  const data = useData<Page<Pick<Technique, 'id' | 'name' | 'revoked' | 'deprecated'>>>(
    `/catalog/attack/releases/${release.id}/techniques?q=${encodeURIComponent(query)}&limit=50&offset=${page * 50}`,
  )
  return (
    <>
      <h3>
        Enterprise v{release.dataset_version} · {release.id.slice(0, 12)}
      </h3>
      <p className="muted-text">
        Estado dos metadados naquela release. Este inventário não comprova execução ou detecção.
      </p>
      <input
        aria-label="Pesquisar no snapshot histórico"
        placeholder="Nome ou ID…"
        maxLength={100}
        value={query}
        onChange={(e) => {
          setQuery(e.target.value)
          setPage(0)
        }}
      />
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        <>
          <p className="muted-text">{data.data?.total} referências no filtro</p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Técnica</th>
                  <th>Estado nesta release</th>
                </tr>
              </thead>
              <tbody>
                {data.data?.items.map((t) => (
                  <tr key={t.id}>
                    <td>{t.id}</td>
                    <td>{t.name}</td>
                    <td>{t.revoked ? 'Revogada' : t.deprecated ? 'Descontinuada' : 'Ativa'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.data?.items.length && <Empty title="Nenhuma técnica neste filtro histórico" />}
          <div className="pagination">
            <button className="button" disabled={page === 0} onClick={() => setPage(page - 1)}>
              Anterior
            </button>
            <span>Página {page + 1}</span>
            <button
              className="button"
              disabled={(page + 1) * 50 >= (data.data?.total ?? 0)}
              onClick={() => setPage(page + 1)}
            >
              Próxima
            </button>
          </div>
        </>
      )}
    </>
  )
}
