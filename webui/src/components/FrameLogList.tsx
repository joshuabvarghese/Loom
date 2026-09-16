import { useEffect, useMemo, useRef, useState } from 'react'
import type { FrameEvent } from '../types'

interface Props {
  frames: FrameEvent[] // chronologically ascending
  selectedSeq: number | null
  onSelect: (seq: number) => void
}

const ROW_HEIGHT = 26
const OVERSCAN = 8

/**
 * A manually-virtualized list: with thousands of frames buffered, rendering
 * one DOM row per frame would make scrolling janky and blow up memory. This
 * only ever mounts the rows currently in (or just outside) the viewport,
 * using a spacer + translated inner container — the same technique
 * react-window uses, without adding the dependency for one list.
 */
export default function FrameLogList({ frames, selectedSeq, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportHeight, setViewportHeight] = useState(300)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const observer = new ResizeObserver(([entry]) => setViewportHeight(entry.contentRect.height))
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Newest last (chronological) is easiest to reason about for a live tail,
  // but a packet-log view reads better newest-first.
  const reversed = useMemo(() => [...frames].reverse(), [frames])

  const totalHeight = reversed.length * ROW_HEIGHT
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT) + OVERSCAN * 2
  const endIndex = Math.min(reversed.length, startIndex + visibleCount)
  const visible = reversed.slice(startIndex, endIndex)

  return (
    <div className="frame-log" ref={containerRef} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
      <div className="frame-log-header">
        <span className="fl-col fl-col-seq">#</span>
        <span className="fl-col fl-col-dir" />
        <span className="fl-col fl-col-type">Type</span>
        <span className="fl-col fl-col-stream">Stream</span>
        <span className="fl-col fl-col-len">Len</span>
        <span className="fl-col fl-col-flags">Flags</span>
        <span className="fl-col fl-col-detail">Detail</span>
      </div>
      <div className="frame-log-scroll-area" style={{ height: totalHeight, position: 'relative' }}>
        <div style={{ transform: `translateY(${startIndex * ROW_HEIGHT}px)` }}>
          {visible.map((f) => (
            <div
              key={f.seq}
              className={`frame-log-row${f.seq === selectedSeq ? ' selected' : ''}`}
              style={{ height: ROW_HEIGHT }}
              onClick={() => onSelect(f.seq)}
            >
              <span className="fl-col fl-col-seq">{f.seq}</span>
              <span className={`fl-col fl-col-dir dir-${f.direction}`}>
                {f.direction === 'in' ? '↓' : '↑'}
              </span>
              <span className="fl-col fl-col-type" data-type={f.type}>
                {f.type}
              </span>
              <span className="fl-col fl-col-stream">
                {f.connId}/{f.streamId}
              </span>
              <span className="fl-col fl-col-len">{f.length}B</span>
              <span className="fl-col fl-col-flags">{f.flags?.join(', ') ?? ''}</span>
              <span className="fl-col fl-col-detail">
                {f.path ?? (f.errorCode ? `err=${f.errorCode}` : f.windowIncrement ? `+${f.windowIncrement}` : '')}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
