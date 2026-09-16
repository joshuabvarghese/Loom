import type { ReactNode } from 'react'

export default function EmptyState({ glyph, children }: { glyph: string; children: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-glyph">{glyph}</div>
      <p>{children}</p>
    </div>
  )
}
