import type { CallRecord, FrameEvent, ReplayResult } from '../types'

// Defends against non-array bodies (e.g. a transient proxy error response)
// rather than letting a bad payload crash the list.
export async function fetchCallHistory(): Promise<CallRecord[]> {
  const res = await fetch('/api/calls')
  if (!res.ok) throw new Error(`GET /api/calls: ${res.status}`)
  const data = await res.json()
  return Array.isArray(data) ? data : []
}

export async function replayCall(id: string, payload?: string): Promise<ReplayResult> {
  const res = await fetch(`/api/replay/${encodeURIComponent(id)}`, {
    method: 'POST',
    ...(payload !== undefined
      ? {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ payload }),
        }
      : {}),
  })
  return res.json()
}

export async function fetchMethodSchema(
  method: string,
  type: 'request' | 'response' = 'request',
): Promise<Record<string, unknown>> {
  const url = `/api/v1/schema?method=${encodeURIComponent(method)}&type=${type}`
  const res = await fetch(url)
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(detail.trim() || `GET ${url}: ${res.status}`)
  }
  return res.json()
}

export type StreamListener = (call: CallRecord) => void
export type ConnStateListener = (connected: boolean) => void

// Auto-reconnects on error with a flat 3s retry (no exponential backoff —
// dev-time event volume is low enough that it doesn't matter). Shared by
// the call stream and the frame stream; onMessage does the type-specific parsing.
function subscribeToSSE<T>(
  path: string,
  onMessage: (msg: T) => void,
  onConnState: ConnStateListener,
): () => void {
  let es: EventSource | null = null
  let retryTimer: ReturnType<typeof setTimeout> | null = null
  let stopped = false

  function connect() {
    if (stopped) return
    es = new EventSource(path)
    es.onopen = () => onConnState(true)
    es.onmessage = (e) => {
      try {
        onMessage(JSON.parse(e.data) as T)
      } catch {
        // ignore malformed frames (e.g. heartbeat comments never reach onmessage)
      }
    }
    es.onerror = () => {
      onConnState(false)
      es?.close()
      es = null
      if (!stopped) retryTimer = setTimeout(connect, 3000)
    }
  }

  connect()

  return () => {
    stopped = true
    if (retryTimer) clearTimeout(retryTimer)
    es?.close()
  }
}

export function subscribeToCallStream(
  onCall: StreamListener,
  onConnState: ConnStateListener,
): () => void {
  return subscribeToSSE('/api/stream', onCall, onConnState)
}

// Returns an empty array (rather than throwing) when the backend wasn't
// built with frame sniffing enabled and /api/frames responds 501 — the
// frame timeline is an optional, best-effort view.
export async function fetchFrameHistory(): Promise<FrameEvent[]> {
  const res = await fetch('/api/frames')
  if (!res.ok) return []
  const data = await res.json()
  return Array.isArray(data) ? data : []
}

export function subscribeToFrameStream(
  onFrame: (frame: FrameEvent) => void,
  onConnState: ConnStateListener,
): () => void {
  return subscribeToSSE('/api/events', onFrame, onConnState)
}
