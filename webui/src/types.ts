// Mirrors internal/recorder/recorder.go — keep in sync with the Go structs.
// This is the single source of truth for the frontend/backend data contract.

export type StreamKind =
  | 'unary'
  | 'server_streaming'
  | 'client_streaming'
  | 'bidi_streaming'

export interface FrameRecord {
  index: number
  json: string
  raw?: string // base64, only populated for replay-capable frames
}

export interface CallRecord {
  id: string
  timestamp: string // RFC3339, from Go's time.Time
  method: string
  streamKind: StreamKind
  request: FrameRecord[]
  response: FrameRecord[]
  statusCode: string
  statusName: string
  grpcMessage?: string
  durationMs: number
  error?: string
  mutated?: boolean
  grpcurlCmd?: string
}

export interface ReplayResult {
  status?: string
  id?: string
  error?: string
}

export type TabID = 'request' | 'response' | 'grpcurl' | 'info'

// Mirrors internal/h2sniff.FrameEvent — real HTTP/2 frame telemetry.
export interface FrameEvent {
  seq: number
  connId: string
  streamId: number
  type: string
  length: number
  flags?: string[]
  direction: 'in' | 'out'
  timestamp: string // RFC3339
  path?: string
  method?: string
  status?: string
  windowIncrement?: number
  errorCode?: string
}
