import type { CallRecord, StreamKind } from '../types'

export function isOK(c: Pick<CallRecord, 'statusCode'>): boolean {
  return c.statusCode === '0' || c.statusCode === '' || !c.statusCode
}

export interface MethodParts {
  pkg: string
  svc: string
  rpc: string
}

/** Splits "/package.Service/Method" (or without the leading slash) into parts. */
export function parseMethod(m: string): MethodParts {
  const clean = m.replace(/^\//, '')
  const slash = clean.lastIndexOf('/')
  if (slash === -1) return { pkg: '', svc: '', rpc: clean }
  const rpc = clean.slice(slash + 1)
  const svcFull = clean.slice(0, slash)
  const dot = svcFull.lastIndexOf('.')
  if (dot === -1) return { pkg: '', svc: svcFull, rpc }
  return { pkg: svcFull.slice(0, dot), svc: svcFull.slice(dot + 1), rpc }
}

const STREAM_LABELS: Record<string, string> = {
  unary: 'unary',
  server_streaming: 'server-stream',
  client_streaming: 'client-stream',
  bidi_streaming: 'bidi',
}

export function streamLabel(k: StreamKind | string): string {
  return STREAM_LABELS[k] ?? k
}

export function fmtDur(ms: number): string {
  if (ms < 1) return (ms * 1000).toFixed(0) + 'µs'
  if (ms < 1000) return ms.toFixed(1) + 'ms'
  return (ms / 1000).toFixed(2) + 's'
}
