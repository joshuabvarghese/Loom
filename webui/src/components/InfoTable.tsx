import { fmtDur, streamLabel } from '../lib/format'
import type { CallRecord } from '../types'

export default function InfoTable({ call }: { call: CallRecord }) {
  const rows: [string, string | number][] = [
    ['id', call.id],
    ['method', call.method],
    ['type', streamLabel(call.streamKind || 'unary')],
    ['status code', call.statusCode || '0'],
    ['status', call.statusName || 'OK'],
    ['duration', fmtDur(call.durationMs)],
    ['timestamp', new Date(call.timestamp).toLocaleString()],
    ['mutated', call.mutated ? 'yes' : 'no'],
    ['req frames', call.request?.length ?? 0],
    ['res frames', call.response?.length ?? 0],
  ]
  if (call.grpcMessage) rows.push(['message', call.grpcMessage])
  if (call.error) rows.push(['error', call.error])

  return (
    <div className="kv-wrap">
      <table className="kv-table">
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td>{k}</td>
              <td>{String(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
