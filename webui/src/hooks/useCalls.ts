import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { fetchCallHistory, subscribeToCallStream } from '../lib/api'
import { isOK } from '../lib/format'
import type { CallRecord } from '../types'

export function useCalls() {
  const [calls, setCalls] = useState<CallRecord[]>([])
  const [connected, setConnected] = useState(false)
  const [selectedID, setSelectedID] = useState<string | null>(null)
  const [filterText, setFilterText] = useState('')

  // Avoids auto-selecting the first live call once the user has picked one.
  const hasSelectedRef = useRef(false)

  useEffect(() => {
    let cancelled = false
    fetchCallHistory()
      .then((hist) => {
        if (!cancelled) setCalls(hist)
      })
      .catch((e) => console.warn('history load:', e))

    const unsubscribe = subscribeToCallStream(
      (call) => {
        setCalls((prev) => [call, ...prev])
        if (!hasSelectedRef.current) {
          hasSelectedRef.current = true
          setSelectedID(call.id)
        }
      },
      setConnected,
    )

    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [])

  const selectCall = useCallback((id: string) => {
    hasSelectedRef.current = true
    setSelectedID(id)
  }, [])

  const clearCalls = useCallback(() => {
    setCalls([])
    setSelectedID(null)
    hasSelectedRef.current = false
  }, [])

  const visibleCalls = useMemo(() => {
    const q = filterText.toLowerCase().trim()
    return q ? calls.filter((c) => c.method.toLowerCase().includes(q)) : calls
  }, [calls, filterText])

  const selectedCall = useMemo(
    () => calls.find((c) => c.id === selectedID) ?? null,
    [calls, selectedID],
  )

  const stats = useMemo(() => {
    const okCount = calls.filter(isOK).length
    return { total: calls.length, ok: okCount, err: calls.length - okCount }
  }, [calls])

  return {
    calls,
    visibleCalls,
    connected,
    selectedID,
    selectedCall,
    filterText,
    setFilterText,
    selectCall,
    clearCalls,
    stats,
  }
}
