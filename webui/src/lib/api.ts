import type { CallRecord, FrameEvent, ReplayResult } from '../types'

/**
 * Fetches the full call history from the backend.
 * Loom's -ui server historically returns 200 with a JSON array here, so we
 * defend against non-array bodies (e.g. transient proxy errors) rather than
 * letting a bad payload crash the list.
 */
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

/**
 * Fetches a draft-07 JSON Schema for a method's request or response message,
 * derived from the backend's gRPC server-reflection descriptor. Powers the
 * live validation/autocomplete in <MonacoPayloadEditor/>.
 */
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

/**
 * Opens an SSE connection at `path` and auto-reconnects on error (3s
 * backoff, single retry loop — no exponential backoff since dev-time event
 * volume is low). Shared by the call stream (/api/stream) and the HTTP/2
 * frame stream (/api/events); onMessage does the type-specific parsing.
 */
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

/** Opens the /api/stream SSE connection for completed calls. */
export function subscribeToCallStream(
  onCall: StreamListener,
  onConnState: ConnStateListener,
): () => void {
  return subscribeToSSE('/api/stream', onCall, onConnState)
}

/**
 * Fetches recently-observed HTTP/2 frame telemetry (newest first). Returns
 * an empty array if the backend wasn't built with frame sniffing enabled
 * (GET /api/frames responds 501) rather than throwing, since the frame
 * timeline is an optional/best-effort view.
 */
export async function fetchFrameHistory(): Promise<FrameEvent[]> {
  const res = await fetch('/api/frames')
  if (!res.ok) return []
  const data = await res.json()
  return Array.isArray(data) ? data : []
}

/** Opens the /api/events SSE connection for live HTTP/2 frame telemetry. */
export function subscribeToFrameStream(
  onFrame: (frame: FrameEvent) => void,
  onConnState: ConnStateListener,
): () => void {
  return subscribeToSSE('/api/events', onFrame, onConnState)
}
