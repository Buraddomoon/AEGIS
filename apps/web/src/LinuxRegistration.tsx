import { useState } from 'react'
import { api, Failure, Loading, Modal, Submit, useAction, useData } from './lib'
import type { Page } from './types'

interface Connection {
  id: string
  revision: number
  owner: string
  isolation: string
  laboratory_id: string
  asset_id: string
  platform: string
  test_id: string
  review_hash: string
}

export function LinuxRegistration({ onClose }: { onClose: () => void }) {
  const connections = useData<Page<Connection> & { mode: 'legacy' | 'registry' }>(
      '/labs/linux/connections?limit=100',
    ),
    [connectionId, setConnectionId] = useState(''),
    [name, setName] = useState('Linux Lab'),
    [owner, setOwner] = useState(''),
    [review, setReview] = useState(''),
    [confirmed, setConfirmed] = useState<string | null>(null),
    { busy, run } = useAction()
  const entry = connections.data?.items?.find((item) => item.id === connectionId)
  const registry = connections.data?.mode === 'registry'
  return (
    <Modal title="Registrar Linux Lab revisado" onClose={onClose}>
      <div className="notice">
        Somente o runner fixado na implantação será cadastrado. Esta ação não executa testes. Após o
        cadastro, valide mTLS e autorize o laboratório. Cada execução exige aprovação de outro
        administrador.
      </div>
      {connections.isLoading && <Loading />}
      {connections.error && <Failure error={connections.error} />}
      {registry && (
        <label>
          Conexão aprovada
          <select
            required
            value={connectionId}
            onChange={(event) => {
              setConnectionId(event.target.value)
              setConfirmed(null)
            }}
          >
            <option value="">Selecione uma revisão</option>
            {connections.data?.items.map((item) => (
              <option key={item.id} value={item.id}>
                {item.id} · revisão {item.revision}
              </option>
            ))}
          </select>
        </label>
      )}
      {entry && (
        <div className="notice registry-review">
          <p>Linux · {entry.test_id}</p>
          <p>
            Laboratório {entry.laboratory_id} · Ativo {entry.asset_id}
          </p>
          <p>
            {entry.owner} · {entry.isolation}
          </p>
        </div>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (!connections.data || connections.error || (registry && !entry)) return
          void run(async () => {
            await api('/labs/linux/register', {
              method: 'POST',
              body: JSON.stringify({
                name,
                owner: entry?.owner ?? owner,
                ...(entry
                  ? { registry_id: entry.id, confirm_registry_hash: entry.review_hash }
                  : {}),
                isolation_review: review,
                confirm_isolation_review: confirmed === (entry?.review_hash ?? 'legacy'),
              }),
            })
            onClose()
          }, 'Binding Linux registrado, ainda sem autorização de execução.')
        }}
      >
        <label>
          Nome
          <input
            required
            minLength={3}
            maxLength={120}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Responsável
          <input
            required
            minLength={3}
            maxLength={120}
            value={entry?.owner ?? owner}
            readOnly={registry}
            onChange={(e) => setOwner(e.target.value)}
          />
        </label>
        <label>
          Revisão do isolamento
          <textarea
            required
            minLength={20}
            maxLength={4000}
            value={review}
            onChange={(e) => setReview(e.target.value)}
            placeholder="Descreva identidade, rede isolada, tmpfs, privilégios e limites revisados."
          />
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            required
            checked={confirmed === (entry?.review_hash ?? 'legacy')}
            onChange={(e) =>
              setConfirmed(e.target.checked ? (entry?.review_hash ?? 'legacy') : null)
            }
          />
          <span>
            Revisei e autorizo o cadastro deste ambiente isolado sob minha responsabilidade.
          </span>
        </label>
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Cancelar
          </button>
          <Submit
            busy={busy || connections.isLoading || !!connections.error || (registry && !entry)}
          >
            Registrar binding
          </Submit>
        </div>
      </form>
    </Modal>
  )
}
