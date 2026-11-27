import { Shield } from 'lucide-react'

export function Brand({ subtitle = false }: { subtitle?: boolean }) {
  return (
    <span className="brand">
      <span className="brand-mark">
        <Shield size={24} strokeWidth={1.5} />
      </span>
      <span>ÆGIS{subtitle && <small>PURPLE TEAM PLATFORM</small>}</span>
    </span>
  )
}
