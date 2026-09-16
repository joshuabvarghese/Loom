import { useEffect, useState } from 'react'
import type { CallRecord } from '../types'
import MonacoPayloadEditor from './MonacoPayloadEditor'
import { replayCall } from '../lib/api'

interface Props {
  call: CallRecord
  onClose: () => void
}

function initialPayload(call: CallRecord): string {
  const raw = call.request?.[0]?.json
  if (!raw) return '{}'
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

export default function ReplayModal({ call, onClose }: Props) {
  const [payload, setPayload] = useState(() => initialPayload(call))
  const [state, setState] = useState<'idle' | 'replaying'>('idle')
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  async function handleReplay() {
    setState('replaying')
    setResult(null)
    try {
      const res = await replayCall(call.id, payload)
      if (res.error) {
        setResult({ ok: false, text: res.error })
      } else {
        setResult({ ok: true, text: `Replayed as ${res.id ?? 'unknown'}` })
      }
    } catch (e) {
      setResult({ ok: false, text: e instanceof Error ? e.message : String(e) })
    } finally {
      setState('idle')
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            Replay <span className="modal-title-method">{call.method}</span>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="modal-body">
          <MonacoPayloadEditor
            methodName={call.method}
            schemaType="request"
            value={payload}
            onChange={(v) => setPayload(v ?? '')}
            height="380px"
          />
        </div>

        <div className="modal-footer">
          {result && (
            <span className={`modal-result ${result.ok ? 'modal-result-ok' : 'modal-result-err'}`}>
              {result.text}
            </span>
          )}
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="replay-btn" onClick={handleReplay} disabled={state === 'replaying'}>
            {state === 'replaying' ? 'Replaying…' : 'Replay'}
          </button>
        </div>
      </div>
    </div>
  )
}
