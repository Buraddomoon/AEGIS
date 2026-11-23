import { Go } from './lib'
import type { CatalogReference } from './types'

interface CatalogNode {
  id: string
  name: string
  reference: string
  revoked: boolean
  deprecated: boolean
}
interface Relationship {
  stix_id: string
  revoked: boolean
  deprecated: boolean
}
interface Relative {
  technique: CatalogNode
  relationship: Relationship | null
}
export interface TechniqueCatalogContext {
  status: 'available' | 'not_provided' | 'legacy_unavailable' | 'technique_absent'
  catalog: CatalogReference
  document_format: string
  parent: Relative | null
  children: Relative[]
  telemetry: {
    relationship: Relationship
    strategy?: CatalogNode
    analytic?: CatalogNode
    component?: CatalogNode
    data_source?: CatalogNode | null
    log_source?: { name: string; channel: string }
  }[]
}
export interface ObservedTelemetry {
  execution_id: string
  run_id: string
  synthetic: boolean
  catalog_release_id: string | null
  catalog_version: string | null
  outcome: string
  collection_complete: boolean
  sources: { source: string; kind: string; synthetic: boolean; event_count: number }[]
}
const statusLabels = {
  legacy_unavailable:
    'O snapshot legado não preserva referências de telemetria nem IDs das relações. Não foram inferidos dados ausentes.',
  technique_absent:
    'Esta técnica está fora da release atual. Não há relações ou fontes desta release para apresentar.',
  not_provided:
    'A release não fornece relações de telemetria para esta técnica. Isso não prova ausência de telemetria no ambiente.',
  available:
    'Referências para planejamento; nenhuma fonte conectada ou coleta é comprovada pelo catálogo.',
}
function retirement(node: { revoked: boolean; deprecated: boolean }) {
  return node.revoked ? ' · Revogada' : node.deprecated ? ' · Descontinuada' : ''
}
function OfficialReference({ node, label }: { node: CatalogNode; label: string }) {
  return (
    <div>
      {label}:{' '}
      <a className="text-link" href={node.reference} target="_blank" rel="noreferrer">
        {node.id} · {node.name}
      </a>
      {retirement(node)}
    </div>
  )
}
export function TechniqueContext({
  context,
  observations,
  mode,
  onNavigate,
}: {
  context?: TechniqueCatalogContext
  observations?: ObservedTelemetry[]
  mode: string
  onNavigate: (id: string) => void
}) {
  function relative(item: Relative) {
    return (
      <li key={item.technique.id}>
        <button className="text-link" onClick={() => onNavigate(item.technique.id)}>
          {item.technique.id} · {item.technique.name}
        </button>
        {retirement(item.technique)}
        {item.relationship && retirement(item.relationship)}
      </li>
    )
  }
  return (
    <>
      <section aria-label="Relações oficiais ATT&CK" className="technique-context">
        <h3>Relações oficiais ATT&CK</h3>
        {context ? (
          <>
            <p className="muted-text">
              Enterprise v{context.catalog.version} · release {context.catalog.release_id}
            </p>
            <h4>Técnica pai</h4>
            {context.parent ? (
              <ul>{relative(context.parent)}</ul>
            ) : (
              <p>Nenhuma técnica pai registrada nesta release.</p>
            )}
            <h4>Subtécnicas</h4>
            {context.children.length ? (
              <ul>{context.children.map(relative)}</ul>
            ) : (
              <p>Nenhuma subtécnica registrada nesta release.</p>
            )}
            <p className="muted-text">
              Navegar mantém o modo e a release selecionados. A cobertura de uma subtécnica não é
              atribuída à técnica pai.
            </p>
            <h3>Telemetria de referência no catálogo</h3>
            <p className="notice">{statusLabels[context.status]}</p>
            {context.telemetry.length > 0 && (
              <details>
                <summary>
                  Consultar {context.telemetry.length} caminhos oficiais de referência
                </summary>
                <ol className="telemetry-paths">
                  {context.telemetry.map((row, i) => (
                    <li key={i}>
                      {row.strategy && <OfficialReference label="Estratégia" node={row.strategy} />}
                      {row.analytic && <OfficialReference label="Analítica" node={row.analytic} />}
                      {row.component && (
                        <OfficialReference label="Componente" node={row.component} />
                      )}
                      {row.data_source && (
                        <OfficialReference label="Fonte" node={row.data_source} />
                      )}
                      {row.log_source ? (
                        <p>
                          Log: {row.log_source.name} · Canal:{' '}
                          {row.log_source.channel || 'Não informado'}
                        </p>
                      ) : (
                        <p>Nome/canal de log não informado neste caminho.</p>
                      )}
                      <small>
                        Relação: {row.relationship.stix_id}
                        {retirement(row.relationship)}
                      </small>
                    </li>
                  ))}
                </ol>
              </details>
            )}
          </>
        ) : (
          <p className="notice warning">Contexto de catálogo indisponível nesta resposta.</p>
        )}
      </section>
      <section aria-label="Telemetria registrada nas execuções" className="technique-context">
        <h3>
          Telemetria registrada nas execuções · {mode === 'demo' ? 'Demo sintético' : 'Linux real'}
        </h3>
        <p>
          Até 30 avaliações concluídas neste modo, com a release original de cada execução. Eventos
          registrados não comprovam conexão atual, correlação ou detecção. Zero eventos não prova
          ausência de telemetria; consulte as evidências e os limites da coleta.
        </p>
        {!observations ? (
          <p>Resumo de telemetria indisponível nesta resposta.</p>
        ) : observations.length === 0 ? (
          <p>Nenhuma avaliação concluída neste modo.</p>
        ) : (
          observations.map((row) => (
            <div className="telemetry-observation" key={row.execution_id}>
              <p>
                {row.synthetic ? 'Sintética' : 'Real'} ·{' '}
                {row.catalog_release_id && row.catalog_version
                  ? `Enterprise v${row.catalog_version} · release ${row.catalog_release_id}`
                  : 'Versão do catálogo não registrada'}
              </p>
              {row.sources.length ? (
                <ul>
                  {row.sources.map((source, i) => (
                    <li key={i}>
                      {source.source} · {source.kind} · {source.event_count} eventos ·{' '}
                      {source.synthetic ? 'Sintéticos' : 'Reais'}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>Nenhum evento registrado nesta avaliação.</p>
              )}
              <p>
                Coleta {row.collection_complete ? 'completa' : 'incompleta'} · Resultado:{' '}
                {row.outcome}
              </p>
              <Go to={`executions/${row.run_id}`}>Evidências da execução</Go>
            </div>
          ))
        )}
      </section>
    </>
  )
}
