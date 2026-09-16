import { useState } from 'react'
import { fmtDur, isOK, parseMethod, streamLabel } from '../lib/format'
import type { CallRecord, TabID } from '../types'
import FramesList from './FramesList'
import GrpcurlView from './GrpcurlView'
import InfoTable from './InfoTable'
import CopyButton from './CopyButton'
import ReplayModal from './ReplayModal'

const TABS: { id: TabID; label: string }[] = [
  { id: 'request', label: 'Request' },
  { id: 'response', label: 'Response' },
  { id: 'grpcurl', label: 'grpcurl' },
  { id: 'info', label: 'Info' },
]

function ReplayButton({ onClick }: { onClick: () => void }) {
  return (
    <button className="replay-btn" onClick={onClick}>
      <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
        <path
          d="M2 9V2l7 3.5L2 9z"
          stroke="currentColor"
          strokeWidth="1.1"
          strokeLinejoin="round"
        />
      </svg>
      Replay
    </button>
  )
}

export default function DetailPane({ call }: { call: CallRecord | null }) {
  const [activeTab, setActiveTab] = useState<TabID>('request')
  const [replayTarget, setReplayTarget] = useState<CallRecord | null>(null)

  if (!call) {
    return (
      <div id="detail">
        <div className="no-selection">
          <div className="arrow">←</div>
          <div>Select a call</div>
        </div>
      </div>
    )
  }

  const parts = parseMethod(call.method)
  const ok = isOK(call)

  return (
    <div id="detail">
      <div id="detailHeader">
        <div className="detail-method">
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
        <div className="detail-meta">
          <span className={`chip ${ok ? 'chip-ok' : 'chip-err'}`}>
            {call.statusName || (ok ? 'OK' : 'ERR')}
          </span>
          {call.mutated && <span className="chip chip-mut">mutated</span>}
          <div className="meta-item">
            <span>duration</span>
            <span className="val">{fmtDur(call.durationMs)}</span>
          </div>
          <div className="meta-item">
            <span>type</span>
            <span className="val">{streamLabel(call.streamKind || 'unary')}</span>
          </div>
          <div className="meta-item">
            <span>id</span>
            <span className="val">{call.id.split('-')[0]}</span>
          </div>
          {call.request && call.request.length > 0 && (
            <ReplayButton onClick={() => setReplayTarget(call)} />
          )}
        </div>
      </div>

      <div id="tabs">
        {TABS.map((t) => (
          <div
            key={t.id}
            className={`tab${t.id === activeTab ? ' active' : ''}`}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </div>
        ))}
      </div>

      <div id="tabContent">
        {activeTab === 'request' && <FramesList frames={call.request || []} />}

        {activeTab === 'response' && (
          <>
            <FramesList frames={call.response || []} />
            {call.grpcMessage && (
              <div className="error-banner">gRPC message: {call.grpcMessage}</div>
            )}
            {call.error && <div className="error-banner">{call.error}</div>}
          </>
        )}

        {activeTab === 'grpcurl' &&
          (call.grpcurlCmd ? (
            <div>
              <div className="section-label">Replay command</div>
              <div className="grpcurl-wrap">
                <div className="code-toolbar">
                  <span className="code-label">grpcurl</span>
                  <CopyButton text={call.grpcurlCmd} />
                </div>
                <GrpcurlView cmd={call.grpcurlCmd} />
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: 12 }}>
              (no grpcurl available for this call)
            </div>
          ))}

        {activeTab === 'info' && <InfoTable call={call} />}
      </div>

      {replayTarget && (
        <ReplayModal key={replayTarget.id} call={replayTarget} onClose={() => setReplayTarget(null)} />
      )}
    </div>
  )
}
