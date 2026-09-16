import { fmtDur, isOK, parseMethod, streamLabel } from '../lib/format'
import type { CallRecord } from '../types'
import EmptyState from './EmptyState'

interface SidebarProps {
  proxyAddr: string
  calls: CallRecord[]
  visibleCalls: CallRecord[]
  selectedID: string | null
  filterText: string
  onFilterChange: (text: string) => void
  onSelect: (id: string) => void
}

function CallListItem({
  call,
  selected,
  onSelect,
}: {
  call: CallRecord
  selected: boolean
  onSelect: (id: string) => void
}) {
  const ok = isOK(call)
  const parts = parseMethod(call.method)
  const t = new Date(call.timestamp).toLocaleTimeString('en', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })

  return (
    <div
      className={`call-item${selected ? ' selected' : ''}`}
      onClick={() => onSelect(call.id)}
    >
      <div className={`call-status-bar ${ok ? 'ok' : 'err'}`} />
      <div className="call-inner">
        <div className="call-method">
          <span className="pkg">
            {parts.pkg}
            {parts.pkg ? '.' : ''}
          </span>
          <span className="svc">
            {parts.svc}
            {parts.svc ? '/' : ''}
          </span>
          <span className="rpc">{parts.rpc}</span>
        </div>
        <div className="call-foot">
          <span className={`chip ${ok ? 'chip-ok' : 'chip-err'}`}>
            {call.statusName || (ok ? 'OK' : 'ERR')}
          </span>
          {call.mutated && <span className="chip chip-mut">mut</span>}
          {call.streamKind && call.streamKind !== 'unary' && (
            <span className="chip chip-kind">{streamLabel(call.streamKind)}</span>
          )}
          <span className="call-time">{t}</span>
          <span className="call-dur">{fmtDur(call.durationMs)}</span>
        </div>
      </div>
    </div>
  )
}

export default function Sidebar({
  proxyAddr,
  calls,
  visibleCalls,
  selectedID,
  filterText,
  onFilterChange,
  onSelect,
}: SidebarProps) {
  return (
    <div id="sidebar">
      <div className="sidebar-toolbar">
        <div className="search-wrap">
          <svg className="search-icon" width="11" height="11" viewBox="0 0 11 11" fill="none">
            <circle cx="4.5" cy="4.5" r="3.5" stroke="currentColor" strokeWidth="1.1" />
            <path d="M7.5 7.5L10 10" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" />
          </svg>
          <input
            id="searchInput"
            placeholder="Filter methods…"
            value={filterText}
            onChange={(e) => onFilterChange(e.target.value)}
          />
        </div>
      </div>

      <div id="callList">
        {visibleCalls.length === 0 ? (
          calls.length === 0 ? (
            <EmptyState glyph="⌀">
              No calls yet.
              <br />
              Point your client at
              <br />
              <code>{proxyAddr}</code>
            </EmptyState>
          ) : (
            <EmptyState glyph="∅">
              No matches for
              <br />
              <code>{filterText}</code>
            </EmptyState>
          )
        ) : (
          visibleCalls.map((c) => (
            <CallListItem key={c.id} call={c} selected={c.id === selectedID} onSelect={onSelect} />
          ))
        )}
      </div>

      <div id="sidebarFooter">
        <div>
          total <span>{calls.length}</span>
        </div>
        {filterText && (
          <div>
            showing <span>{visibleCalls.length}</span>
          </div>
        )}
      </div>
    </div>
  )
}
