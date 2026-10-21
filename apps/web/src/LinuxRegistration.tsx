import { useState } from 'react'
import { api, Modal, Submit, useAction } from './lib'

export function LinuxRegistration({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('Linux Lab'),
    [owner, setOwner] = useState(''),
    [review, setReview] = useState(''),
    [confirmed, setConfirmed] = useState(false),
    { busy, run } = useAction()
  return (
    <Modal title="Registrar Linux Lab revisado" onClose={onClose}>
      <div className="notice">
        Somente o runner fixado na implantação será cadastrado. Esta ação não executa testes. Após o
        cadastro, valide mTLS e autorize o laboratório. Cada execução exige aprovação de outro
        administrador.
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          void run(async () => {
            await api('/labs/linux/register', {
              method: 'POST',
              body: JSON.stringify({
                name,
                owner,
                isolation_review: review,
                confirm_isolation_review: confirmed,
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
            value={owner}
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
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
          />
          <span>
            Revisei e autorizo o cadastro deste ambiente isolado sob minha responsabilidade.
          </span>
        </label>
        <div className="form-actions">
          <button type="button" className="button" onClick={onClose}>
            Cancelar
          </button>
          <Submit busy={busy}>Registrar binding</Submit>
        </div>
      </form>
    </Modal>
  )
}
