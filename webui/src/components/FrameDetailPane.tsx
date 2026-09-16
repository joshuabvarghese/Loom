import type { ReactNode } from 'react'
import type { FrameEvent } from '../types'

interface Props {
  frame: FrameEvent | null
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="frame-detail-row">
      <span className="fd-label">{label}</span>
      <span className="fd-value">{value}</span>
    </div>
  )
}

export default function FrameDetailPane({ frame }: Props) {
  if (!frame) {
    return (
      <div className="frame-detail no-selection">
        <div className="arrow">←</div>
        <div>Select a frame</div>
      </div>
    )
  }

  return (
    <div className="frame-detail">
      <div className="frame-detail-title" data-type={frame.type}>
        {frame.type}
      </div>
      <Row label="seq" value={frame.seq} />
      <Row label="connection" value={frame.connId} />
      <Row label="stream" value={frame.streamId} />
      <Row label="direction" value={frame.direction === 'in' ? 'inbound (↓)' : 'outbound (↑)'} />
      <Row label="length" value={`${frame.length} bytes`} />
      <Row label="flags" value={frame.flags?.join(', ')} />
      <Row label="timestamp" value={new Date(frame.timestamp).toISOString()} />
      <Row label=":method" value={frame.method} />
      <Row label=":path" value={frame.path} />
      <Row label=":status" value={frame.status} />
      <Row
        label="window increment"
        value={frame.windowIncrement ? `+${frame.windowIncrement}` : undefined}
      />
      <Row label="error code" value={frame.errorCode} />
    </div>
  )
}
