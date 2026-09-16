import { useEffect, useMemo, useRef, useState } from 'react'
import type { FrameEvent } from '../types'

interface Props {
  frames: FrameEvent[]
  selectedSeq: number | null
  onSelect: (seq: number) => void
}

const ROW_HEIGHT = 24
const HEADER_HEIGHT = 28
const LABEL_WIDTH = 168
const PX_PER_MS = 0.6
const MIN_TIMELINE_WIDTH = 600
const MARKER_RADIUS = 4

const TYPE_COLORS: Record<string, string> = {
  HEADERS: '#3b7eff', // accent
  DATA: '#22c55e', // green
  RST_STREAM: '#f43f5e', // red
  WINDOW_UPDATE: '#f59e0b', // amber
  SETTINGS: '#a855f7', // purple
  GOAWAY: '#f43f5e',
  PING: '#22d3ee', // cyan
  PRIORITY: '#8892a4', // text2
  PUSH_PROMISE: '#8892a4',
}

function colorFor(type: string): string {
  return TYPE_COLORS[type] ?? '#4b5568'
}

interface Row {
  key: string
  connId: string
  streamId: number
  isConnRow: boolean // streamId 0 (SETTINGS/PING/GOAWAY/connection-level WINDOW_UPDATE)
  firstMs: number
  lastMs: number
  frames: FrameEvent[]
}

/** Groups frames into rows: one connection-level row (stream 0) plus one row per real stream, per connection. */
function buildRows(frames: FrameEvent[], t0: number): Row[] {
  const rows = new Map<string, Row>()
  for (const f of frames) {
    const key = `${f.connId}:${f.streamId}`
    const ms = new Date(f.timestamp).getTime() - t0
    let row = rows.get(key)
    if (!row) {
      row = {
        key,
        connId: f.connId,
        streamId: f.streamId,
        isConnRow: f.streamId === 0,
        firstMs: ms,
        lastMs: ms,
        frames: [],
      }
      rows.set(key, row)
    }
    row.frames.push(f)
    row.firstMs = Math.min(row.firstMs, ms)
    row.lastMs = Math.max(row.lastMs, ms)
  }
  return Array.from(rows.values()).sort((a, b) => {
    if (a.connId !== b.connId) return a.connId < b.connId ? -1 : 1
    if (a.isConnRow !== b.isConnRow) return a.isConnRow ? -1 : 1
    return a.streamId - b.streamId
  })
}

export default function Http2FrameTimeline({ frames, selectedSeq, onSelect }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ frame: FrameEvent; x: number; y: number } | null>(null)

  const t0 = frames.length ? new Date(frames[0].timestamp).getTime() : 0
  const rows = useMemo(() => buildRows(frames, t0), [frames, t0])

  const durationMs = frames.length
    ? new Date(frames[frames.length - 1].timestamp).getTime() - t0
    : 0
  const timelineWidth = Math.max(MIN_TIMELINE_WIDTH, durationMs * PX_PER_MS + 40)
  const canvasWidth = LABEL_WIDTH + timelineWidth
  const canvasHeight = HEADER_HEIGHT + rows.length * ROW_HEIGHT + 8

  // Flat index of every drawn marker, for hit-testing on click/hover.
  const markers = useMemo(() => {
    const out: { frame: FrameEvent; x: number; y: number; rowKey: string }[] = []
    rows.forEach((row, i) => {
      const y = HEADER_HEIGHT + i * ROW_HEIGHT + ROW_HEIGHT / 2
      for (const f of row.frames) {
        const ms = new Date(f.timestamp).getTime() - t0
        const x = LABEL_WIDTH + 8 + ms * PX_PER_MS
        out.push({ frame: f, x, y: f.direction === 'in' ? y - 5 : y + 5, rowKey: row.key })
      }
    })
    return out
  }, [rows, t0])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const dpr = window.devicePixelRatio || 1
    canvas.width = canvasWidth * dpr
    canvas.height = canvasHeight * dpr
    canvas.style.width = `${canvasWidth}px`
    canvas.style.height = `${canvasHeight}px`
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.scale(dpr, dpr)

    ctx.clearRect(0, 0, canvasWidth, canvasHeight)

    // Row backgrounds + labels
    rows.forEach((row, i) => {
      const y = HEADER_HEIGHT + i * ROW_HEIGHT
      ctx.fillStyle = i % 2 === 0 ? 'rgba(255,255,255,0.015)' : 'transparent'
      ctx.fillRect(0, y, canvasWidth, ROW_HEIGHT)

      ctx.fillStyle = row.isConnRow ? '#8892a4' : '#e4e8f0'
      ctx.font = row.isConnRow ? '10px "GeistMono", monospace' : '11px "GeistMono", monospace'
      ctx.textBaseline = 'middle'
      const label = row.isConnRow ? `${row.connId} · conn` : `${row.connId} · stream ${row.streamId}`
      ctx.fillText(truncateLabel(ctx, label, LABEL_WIDTH - 16), 8, y + ROW_HEIGHT / 2)

      // Stream lifetime bar
      const barY = y + ROW_HEIGHT / 2
      const x1 = LABEL_WIDTH + 8 + row.firstMs * PX_PER_MS
      const x2 = LABEL_WIDTH + 8 + row.lastMs * PX_PER_MS
      ctx.strokeStyle = 'rgba(136,146,164,0.35)'
      ctx.lineWidth = 1.5
      ctx.beginPath()
      ctx.moveTo(x1, barY)
      ctx.lineTo(Math.max(x2, x1 + 1), barY)
      ctx.stroke()
    })

    // Vertical separator between labels and timeline
    ctx.strokeStyle = '#1e2330'
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.moveTo(LABEL_WIDTH, 0)
    ctx.lineTo(LABEL_WIDTH, canvasHeight)
    ctx.stroke()

    // Frame markers
    for (const m of markers) {
      const isSelected = m.frame.seq === selectedSeq
      ctx.fillStyle = colorFor(m.frame.type)
      ctx.beginPath()
      if (m.frame.direction === 'in') {
        // Upward-pointing triangle: inbound
        ctx.moveTo(m.x, m.y - MARKER_RADIUS)
        ctx.lineTo(m.x - MARKER_RADIUS, m.y + MARKER_RADIUS)
        ctx.lineTo(m.x + MARKER_RADIUS, m.y + MARKER_RADIUS)
      } else {
        // Downward-pointing triangle: outbound
        ctx.moveTo(m.x, m.y + MARKER_RADIUS)
        ctx.lineTo(m.x - MARKER_RADIUS, m.y - MARKER_RADIUS)
        ctx.lineTo(m.x + MARKER_RADIUS, m.y - MARKER_RADIUS)
      }
      ctx.closePath()
      ctx.fill()
      if (isSelected) {
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 1.5
        ctx.stroke()
      }
    }
  }, [rows, markers, canvasWidth, canvasHeight, selectedSeq])

  function hitTest(clientX: number, clientY: number) {
    const canvas = canvasRef.current
    if (!canvas) return null
    const rect = canvas.getBoundingClientRect()
    const x = clientX - rect.left
    const y = clientY - rect.top
    let best: { frame: FrameEvent; x: number; y: number } | null = null
    let bestDist = 8 // px hit-radius
    for (const m of markers) {
      const d = Math.hypot(m.x - x, m.y - y)
      if (d < bestDist) {
        bestDist = d
        best = m
      }
    }
    return best
  }

  return (
    <div className="h2-timeline">
      {frames.length === 0 ? (
        <div className="h2-timeline-empty">
          Waiting for HTTP/2 frames… make a gRPC call through the proxy to see them here.
        </div>
      ) : (
        <div className="h2-timeline-scroll" ref={scrollRef}>
          <canvas
            ref={canvasRef}
            onMouseMove={(e) => {
              const hit = hitTest(e.clientX, e.clientY)
              setHover(hit ? { frame: hit.frame, x: e.clientX, y: e.clientY } : null)
            }}
            onMouseLeave={() => setHover(null)}
            onClick={(e) => {
              const hit = hitTest(e.clientX, e.clientY)
              if (hit) onSelect(hit.frame.seq)
            }}
          />
        </div>
      )}
      {hover && (
        <div className="h2-timeline-tooltip" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <span className="h2-tooltip-type" style={{ color: colorFor(hover.frame.type) }}>
            {hover.frame.type}
          </span>
          <span>
            {' '}
            stream {hover.frame.streamId} · {hover.frame.direction} · {hover.frame.length}B
          </span>
          {hover.frame.path && <div className="h2-tooltip-path">{hover.frame.path}</div>}
        </div>
      )}
      <div className="h2-legend">
        {Object.entries(TYPE_COLORS).map(([type, color]) => (
          <span key={type} className="h2-legend-item">
            <span className="h2-legend-dot" style={{ background: color }} />
            {type}
          </span>
        ))}
      </div>
    </div>
  )
}

function truncateLabel(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string {
  if (ctx.measureText(text).width <= maxWidth) return text
  let lo = 0
  let hi = text.length
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (ctx.measureText(text.slice(0, mid) + '…').width <= maxWidth) lo = mid
    else hi = mid - 1
  }
  return text.slice(0, lo) + '…'
}
