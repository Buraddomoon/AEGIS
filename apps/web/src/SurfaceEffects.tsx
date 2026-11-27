import { useEffect } from 'react'

// One delegated listener for all pages: pointer feedback never updates React state.
const surfaces =
  '.panel, .metric, .login-card, .workflow-steps > a, .technique-cell, .evidence-button'

export function SurfaceEffects() {
  useEffect(() => {
    const preference = window.matchMedia(
      '(hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference)',
    )
    let current: HTMLElement | null = null
    let frame = 0
    let x = 0,
      y = 0
    const clear = () => {
      if (frame) cancelAnimationFrame(frame)
      frame = 0
      current?.removeAttribute('data-glow-active')
      current = null
    }
    const paint = () => {
      frame = 0
      if (!current?.isConnected) return clear()
      const bounds = current.getBoundingClientRect()
      current.style.setProperty('--glow-x', `${x - bounds.left}px`)
      current.style.setProperty('--glow-y', `${y - bounds.top}px`)
    }
    const move = (event: PointerEvent) => {
      if (!preference.matches || event.pointerType === 'touch') return clear()
      const target =
        event.target instanceof Element ? event.target.closest<HTMLElement>(surfaces) : null
      if (target !== current) {
        clear()
        current = target
        current?.setAttribute('data-glow-active', '')
      }
      if (!current) return
      x = event.clientX
      y = event.clientY
      if (!frame) frame = requestAnimationFrame(paint)
    }
    const leave = (event: PointerEvent) => {
      if (!event.relatedTarget) clear()
    }
    document.addEventListener('pointermove', move, { passive: true })
    document.addEventListener('pointerout', leave, { passive: true })
    window.addEventListener('blur', clear)
    window.addEventListener('scroll', clear, { passive: true, capture: true })
    preference.addEventListener('change', clear)
    return () => {
      clear()
      document.removeEventListener('pointermove', move)
      document.removeEventListener('pointerout', leave)
      window.removeEventListener('blur', clear)
      window.removeEventListener('scroll', clear, true)
      preference.removeEventListener('change', clear)
    }
  }, [])
  return null
}
