import { useState } from 'react'
import { api, date, Failure, Loading, Modal, Panel, Submit, useAction, useData } from './lib'
import type { User } from './types'

type Sessions = { total: number; items: { expires_at: string; current: boolean }[] }

export function endSession(message: string) {
  window.dispatchEvent(new CustomEvent('aegis-session-ended', { detail: message }))
}

export function AccountSettings({ user }: { user: User }) {
  const [changing, setChanging] = useState(false)
  return (
    <Panel title="Minha conta" subtitle={`${user.username} · Senha e sessões pessoais.`}>
      <div className="account-controls">
        <button className="button" onClick={() => setChanging(true)}>
          Trocar minha senha
        </button>
        <SessionsControl user={user} self />
      </div>
      {changing && <PasswordForm onClose={() => setChanging(false)} />}
    </Panel>
  )
}

function PasswordForm({ target, onClose }: { target?: User; onClose: () => void }) {
  const [current, setCurrent] = useState(''),
    [password, setPassword] = useState(''),
    [confirmation, setConfirmation] = useState(''),
    { busy, run } = useAction()
  const own = !target
  return (
    <Modal
      title={own ? 'Trocar minha senha' : `Redefinir senha · ${target.username}`}
      onClose={() => {
        if (!busy) onClose()
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (password !== confirmation) return
          void run(async () => {
            try {
              await api(own ? '/auth/password' : `/users/${target.id}/password`, {
                method: 'POST',
                body: JSON.stringify(
                  own
                    ? { current_password: current, new_password: password, confirm: true }
                    : { new_password: password, confirm: true },
                ),
              })
              onClose()
              if (own) endSession('Senha alterada. Entre novamente com a nova senha.')
            } finally {
              setCurrent('')
              setPassword('')
              setConfirmation('')
            }
          }, 'Senha redefinida; as sessões da conta foram encerradas.')
        }}
      >
        <fieldset disabled={busy}>
          {own && (
            <label>
              Senha atual
              <input
                type="password"
                required
                maxLength={128}
                autoComplete="current-password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
              />
            </label>
          )}
          <label>
            Nova senha
            <input
              type="password"
              required
              minLength={12}
              maxLength={128}
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <label>
            Confirmar nova senha
            <input
              type="password"
              required
              minLength={12}
              maxLength={128}
              autoComplete="new-password"
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
            />
          </label>
          {confirmation && password !== confirmation && (
            <p role="alert">As senhas devem ser iguais.</p>
          )}
          <p>Todas as sessões desta conta serão encerradas. Confirme para continuar.</p>
          <Submit busy={busy || password !== confirmation}>Confirmar troca de senha</Submit>
        </fieldset>
      </form>
    </Modal>
  )
}

export function SessionsControl({ user, self }: { user: User; self: boolean }) {
  const data = useData<Sessions>(`/users/${user.id}/sessions`),
    [confirming, setConfirming] = useState(false),
    { busy, run } = useAction()
  return (
    <div className="session-controls">
      <h3>Sessões de {user.username}</h3>
      {data.isLoading ? (
        <Loading />
      ) : data.error ? (
        <Failure error={data.error} />
      ) : (
        <>
          <p>{data.data?.total} sessões vigentes</p>
          <ul>
            {data.data?.items.map((s, i) => (
              <li key={i}>
                Expira em {date(s.expires_at)}
                {s.current ? ' · Esta sessão' : ''}
              </li>
            ))}
          </ul>
          <button
            className="button"
            disabled={busy || !data.data?.total}
            onClick={() => setConfirming(true)}
          >
            Encerrar todas as sessões
          </button>
        </>
      )}
      {confirming && (
        <Modal
          title={`Encerrar sessões · ${user.username}`}
          onClose={() => {
            if (!busy) setConfirming(false)
          }}
        >
          <p>
            {self ? 'Você precisará entrar novamente.' : 'A conta precisará entrar novamente.'}{' '}
            Nenhuma senha será alterada.
          </p>
          <button
            className="button danger"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await api(`/users/${user.id}/sessions/revoke`, {
                  method: 'POST',
                  body: JSON.stringify({ confirm: true }),
                })
                setConfirming(false)
                if (self) endSession('Sessões encerradas. Entre novamente para continuar.')
              }, 'Sessões encerradas.')
            }
          >
            Confirmar encerramento
          </button>
        </Modal>
      )}
    </div>
  )
}

export function UserMaintenance({
  target,
  current,
  onClose,
}: {
  target: User
  current: User
  onClose: () => void
}) {
  const [role, setRole] = useState(target.role),
    [active, setActive] = useState(target.active),
    [confirmed, setConfirmed] = useState(false),
    [password, setPassword] = useState(false),
    { busy, run } = useAction()
  const self = target.id === current.id
  return (
    <Modal
      title={`Administrar · ${target.username}`}
      onClose={() => {
        if (!busy) onClose()
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void run(async () => {
            await api(`/users/${target.id}`, {
              method: 'PATCH',
              body: JSON.stringify({ role, active, confirm: true }),
            })
            onClose()
            if (self && (role !== target.role || active !== target.active))
              endSession('Conta atualizada. Entre novamente para continuar.')
          }, 'Conta atualizada; sessões afetadas encerradas.')
        }}
      >
        <fieldset disabled={busy}>
          <label>
            Papel da conta
            <select
              value={role}
              onChange={(e) => {
                setRole(e.target.value as User['role'])
                setConfirmed(false)
              }}
            >
              <option value="viewer">Visualizador</option>
              <option value="operator">Operador</option>
              <option value="administrator">Administrador</option>
            </select>
          </label>
          <label className="account-confirm">
            <input
              type="checkbox"
              checked={active}
              onChange={(e) => {
                setActive(e.target.checked)
                setConfirmed(false)
              }}
            />
            Conta ativa
          </label>
          <p>
            Alterar papel ou situação encerra todas as sessões da conta e revalida autorizações de
            execução. O último administrador ativo é protegido.
          </p>
          <label className="account-confirm">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            Confirmo a alteração de {target.username}
          </label>
          <Submit busy={busy || !confirmed || (role === target.role && active === target.active)}>
            Salvar conta
          </Submit>
        </fieldset>
      </form>
      {!self && (
        <button className="button" disabled={busy} onClick={() => setPassword(true)}>
          Redefinir senha desta conta
        </button>
      )}
      <SessionsControl user={target} self={self} />
      {password && <PasswordForm target={target} onClose={() => setPassword(false)} />}
    </Modal>
  )
}
