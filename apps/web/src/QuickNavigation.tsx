import { useEffect, useRef, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowUpRight, Search } from 'lucide-react'
import { Modal } from './lib'

type Group = { group: string; items: { id: string; label: string; icon: LucideIcon }[] }
const normalize = (text: string) =>
  text
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()

export function QuickNavigation({ groups, onClose }: { groups: Group[]; onClose: () => void }) {
  const [search, setSearch] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    inputRef.current?.focus()
  }, [])
  const matches = groups
    .flatMap((group) => group.items.map((item) => ({ ...item, group: group.group })))
    .filter((item) => normalize(`${item.label} ${item.group}`).includes(normalize(search.trim())))
  return (
    <Modal title="Ir para uma página" onClose={onClose}>
      <div className="quick-nav-search">
        <Search size={18} aria-hidden="true" />
        <input
          ref={inputRef}
          type="search"
          aria-label="Pesquisar páginas"
          placeholder="Campanhas, relatórios, laboratórios…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && matches.length) {
              window.location.hash = matches[0].id
              onClose()
            }
          }}
        />
      </div>
      <p className="sr-only" role="status">
        {matches.length} páginas encontradas
      </p>
      <nav className="quick-nav-results" aria-label="Resultados da busca">
        {matches.map((item) => (
          <a key={item.id} href={`#${item.id}`} onClick={onClose}>
            <item.icon size={18} />
            <span>
              {item.label}
              <small>{item.group}</small>
            </span>
            <ArrowUpRight size={16} />
          </a>
        ))}
        {!matches.length && (
          <div className="quick-nav-empty">Nenhuma página encontrada. Tente outro termo.</div>
        )}
      </nav>
      <div className="quick-nav-help">
        <span>
          <kbd>Enter</kbd> abre o primeiro resultado
        </span>
        <span>
          <kbd>Esc</kbd> fecha
        </span>
      </div>
    </Modal>
  )
}
