import { useState } from 'react'
import { Badge, date, Empty, Failure, Loading, Modal, useData } from './lib'
import type { Asset, Page } from './types'

export function LabAssets({ laboratoryId }: { laboratoryId: string }) {
  const data = useData<Page<Asset>>(`/assets?laboratory_id=${encodeURIComponent(laboratoryId)}`),
    [selected, setSelected] = useState<Asset | null>(null)
  if (data.isLoading) return <Loading />
  if (data.error) return <Failure error={data.error} />
  return (
    <>
      <h3>Ativos e capacidade</h3>
      {!data.data?.items.length && <Empty title="Nenhum ativo cadastrado" />}
      {data.data?.items
        .filter((asset) => asset.laboratory_id === laboratoryId)
        .map((asset) => (
          <div key={asset.id} className="notice lab-asset">
            <p>
              <strong>{asset.name}</strong> · {asset.platform} ·{' '}
              <Badge value={asset.connection_status} />
            </p>
            <p>
              {asset.authorized ? 'Autorizado' : 'Revogado'} ·{' '}
              {asset.synthetic ? 'Sintético' : 'Real'}
            </p>
            <p className="mono muted-text">
              Ativo {asset.id} · Identidade externa {asset.external_id}
            </p>
            <p>
              {asset.available_test_ids.length
                ? `Perfis revisados: ${asset.available_test_ids.join(', ')}`
                : 'Sem capacidade de execução revisada'}
            </p>
            <button className="text-link" onClick={() => setSelected(asset)}>
              Histórico do ativo {asset.name}
            </button>
          </div>
        ))}
      {selected && (
        <AssetHistory key={selected.id} asset={selected} onClose={() => setSelected(null)} />
      )}
    </>
  )
}

function AssetHistory({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const [page, setPage] = useState(0),
    history = useData<
      Page<{ id: string; run_id: string; state: string; created_at: string; synthetic: boolean }>
    >(`/assets/${encodeURIComponent(asset.id)}/history?offset=${page * 25}&limit=25`)
  return (
    <Modal title={`Histórico: ${asset.name}`} onClose={onClose}>
      {history.isLoading ? (
        <Loading />
      ) : history.error ? (
        <Failure error={history.error} />
      ) : (
        <>
          {!history.data?.items.length && <Empty title="Nenhuma execução registrada" />}
          {history.data?.items.map((item) => (
            <p key={item.id}>
              <a className="text-link" href={`#executions/${item.run_id}`}>
                {date(item.created_at)} · {item.state} · {item.synthetic ? 'sintético' : 'real'}
              </a>
            </p>
          ))}
          <div className="pagination">
            <button className="button" disabled={!page} onClick={() => setPage(page - 1)}>
              Anterior
            </button>
            <span>{history.data?.total ?? 0} registros</span>
            <button
              className="button"
              disabled={(page + 1) * 25 >= (history.data?.total ?? 0)}
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
