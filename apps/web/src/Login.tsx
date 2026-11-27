import { useState } from 'react'
import {
  ArrowRight,
  ChevronRight,
  Eye,
  EyeOff,
  Fingerprint,
  LoaderCircle,
  LockKeyhole,
  Radio,
  Shield,
  ShieldCheck,
  Target,
} from 'lucide-react'
import { api } from './lib'
import { Brand } from './Brand'
import type { User } from './types'

export default function Login({
  onLogin,
  message,
}: {
  onLogin: (user: User) => void | Promise<void>
  message?: string
}) {
  const [username, setUsername] = useState(''),
    [password, setPassword] = useState('')
  const [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [visible, setVisible] = useState(false)
  return (
    <div className="login-page">
      <header className="login-header">
        <Brand />
        <span>
          <LockKeyhole size={14} /> ACESSO AO WORKSPACE
        </span>
      </header>
      <div className="login-layout">
        <section className="login-brand" aria-label="Sobre o AEGIS">
          <span className="eyebrow">SIMULAÇÃO CONTROLADA. DEFESA VALIDADA.</span>
          <h1>
            Confiança se constrói.
            <br />
            <span>Com evidências.</span>
          </h1>
          <p>
            Do comportamento simulado à detecção comprovada. Um workspace para conectar operações e
            entender o que sua defesa realmente observa.
          </p>
          <div className="defense-visual" aria-hidden="true">
            <div className="defense-orbit orbit-outer" />
            <div className="defense-orbit orbit-inner" />
            <div className="defense-core">
              <Shield size={64} strokeWidth={1} />
              <span>Æ</span>
            </div>
            <span className="orbit-node node-offensive">
              <Target size={16} /> Simular
            </span>
            <span className="orbit-node node-defensive">
              <Radio size={16} /> Observar
            </span>
            <span className="orbit-node node-validation">
              <ShieldCheck size={16} /> Validar
            </span>
            <span className="defense-caption">OPERAÇÕES CONECTADAS POR EVIDÊNCIAS</span>
          </div>
        </section>
        <section className="login-access">
          <form
            className="login-card"
            aria-label="Acessar workspace"
            onSubmit={async (event) => {
              event.preventDefault()
              if (busy) return
              setBusy(true)
              setError('')
              try {
                const result = await api<{ user: User }>('/auth/login', {
                  method: 'POST',
                  body: JSON.stringify({ username, password }),
                })
                await onLogin(result.user)
              } catch (err) {
                setError((err as Error).message)
              } finally {
                setBusy(false)
              }
            }}
          >
            <span className="login-access-icon">
              <Fingerprint size={25} strokeWidth={1.5} />
            </span>
            <span className="eyebrow">SEU CENTRO DE VALIDAÇÃO</span>
            <h2>Bem-vindo ao ÆGIS</h2>
            <p>Entre com sua conta para acessar o workspace.</p>
            {message && (
              <div className="notice" role="status">
                {message}
              </div>
            )}
            <label>
              Usuário
              <input
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                required
                placeholder="Seu usuário"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                disabled={busy}
              />
            </label>
            <label htmlFor="login-password">Senha</label>
            <div className="password-field">
              <input
                id="login-password"
                type={visible ? 'text' : 'password'}
                autoComplete="current-password"
                required
                placeholder="Sua senha"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                disabled={busy}
                aria-describedby={error ? 'login-error' : undefined}
              />
              <button
                type="button"
                className="icon-button"
                aria-label={visible ? 'Ocultar senha' : 'Mostrar senha'}
                aria-pressed={visible}
                onClick={() => setVisible(!visible)}
              >
                {visible ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
            {error && (
              <div id="login-error" className="notice danger" role="alert">
                {error}
              </div>
            )}
            <button disabled={busy} className="button primary" type="submit">
              {busy ? (
                <>
                  <LoaderCircle size={17} className="spin" />
                  Autenticando…
                </>
              ) : (
                <>
                  Entrar no workspace
                  <ArrowRight size={17} />
                </>
              )}
            </button>
            <div className="login-security">
              <LockKeyhole size={14} />
              <span>Acesso restrito a contas autorizadas</span>
            </div>
          </form>
          <div className="login-context">
            <FlaskIcon />
            <p>
              <strong>Explore com o Demo Lab</strong>Simulações sintéticas para conhecer o fluxo.
              Laboratórios reais exigem configuração e autorização específicas.
            </p>
            <ChevronRight size={16} />
          </div>
        </section>
      </div>
      <footer className="login-footer">
        <span>ÆGIS · Purple Team & Detection Validation</span>
        <span>Somente em ambientes autorizados</span>
      </footer>
    </div>
  )
}

function FlaskIcon() {
  return <Target size={20} aria-hidden="true" />
}
