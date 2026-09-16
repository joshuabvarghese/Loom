import { useState } from 'react'
import JsonView from './JsonView'
import CopyButton from './CopyButton'
import type { FrameRecord } from '../types'

function SingleFrame({ frame }: { frame: FrameRecord }) {
  const json = frame.json || '(empty)'
  return (
    <div className="code-wrap">
      <div className="code-toolbar">
        <span className="code-label">frame 0 · JSON</span>
        <CopyButton text={json} />
      </div>
      <JsonView json={json} />
    </div>
  )
}

function CollapsibleFrame({ frame, index }: { frame: FrameRecord; index: number }) {
  const [collapsed, setCollapsed] = useState(false)
  const json = frame.json || '(empty)'
  return (
    <div className={`frame-item${collapsed ? ' collapsed' : ''}`}>
      <div className="frame-header" onClick={() => setCollapsed((c) => !c)}>
        <span className="frame-idx">{index}</span>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>
          JSON
        </span>
        <span style={{ marginLeft: 'auto', marginRight: 8 }} onClick={(e) => e.stopPropagation()}>
          <CopyButton text={json} />
        </span>
        <span className="frame-chevron">▾</span>
      </div>
      <JsonView json={json} />
    </div>
  )
}

export default function FramesList({ frames }: { frames: FrameRecord[] }) {
  if (frames.length === 0) {
    return (
      <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: 12 }}>
        (no frames)
      </div>
    )
  }
  if (frames.length === 1) return <SingleFrame frame={frames[0]} />
  return (
    <div className="frames-list">
      {frames.map((f, i) => (
        <CollapsibleFrame key={i} frame={f} index={i} />
      ))}
    </div>
  )
}
