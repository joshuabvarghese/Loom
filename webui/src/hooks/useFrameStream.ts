import { useEffect, useMemo, useState } from 'react'
import { fetchFrameHistory, subscribeToFrameStream } from '../lib/api'
import type { FrameEvent } from '../types'

// Frames are far higher-volume than calls (dozens per RPC). Cap the
// in-memory buffer so a long-running session doesn't grow without bound —
// this trims oldest-first, same eviction policy as the backend's ring buffer.
const MAX_FRAMES = 5000

export function useFrameStream() {
  const [frames, setFrames] = useState<FrameEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null)

  useEffect(() => {
    let cancelled = false

    fetchFrameHistory()
      .then((hist) => {
        if (cancelled) return
        // History arrives newest-first; store chronologically ascending so
        // the timeline can just append live frames to the end.
        setFrames([...hist].reverse())
      })
      .catch((e) => console.warn('frame history load:', e))

    const unsubscribe = subscribeToFrameStream(
      (frame) => {
        setFrames((prev) => {
          const next = prev.length >= MAX_FRAMES ? prev.slice(prev.length - MAX_FRAMES + 1) : prev
          return [...next, frame]
        })
      },
      setConnected,
    )

    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [])

  const selectedFrame = useMemo(
    () => frames.find((f) => f.seq === selectedSeq) ?? null,
    [frames, selectedSeq],
  )

  const clearFrames = () => {
    setFrames([])
    setSelectedSeq(null)
  }

  return { frames, connected, selectedSeq, setSelectedSeq, selectedFrame, clearFrames }
}
