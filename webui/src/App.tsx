import { useEffect, useState } from 'react'
import TopBar from './components/TopBar'
import Sidebar from './components/Sidebar'
import DetailPane from './components/DetailPane'
import FrameInspector from './components/FrameInspector'
import { useCalls } from './hooks/useCalls'
import { fetchConfig } from './lib/config'

type View = 'calls' | 'frames'

function ViewTabs({ view, onChange }: { view: View; onChange: (v: View) => void }) {
  return (
    <div className="view-tabs">
      <button
        className={`view-tab${view === 'calls' ? ' active' : ''}`}
        onClick={() => onChange('calls')}
      >
        Calls
      </button>
      <button
        className={`view-tab${view === 'frames' ? ' active' : ''}`}
        onClick={() => onChange('frames')}
      >
        HTTP/2 Frames
      </button>
    </div>
  )
}

export default function App() {
  const [proxyAddr, setProxyAddr] = useState('')
  const [view, setView] = useState<View>('calls')
  const {
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
  } = useCalls()

  useEffect(() => {
    fetchConfig()
      .then((cfg) => setProxyAddr(cfg.proxyAddr))
      .catch((e) => console.warn('config load:', e))
  }, [])

  return (
    <div id="app">
      <TopBar
        proxyAddr={proxyAddr}
        connected={connected}
        total={stats.total}
        ok={stats.ok}
        err={stats.err}
        onClear={clearCalls}
      />
      <ViewTabs view={view} onChange={setView} />
      {view === 'calls' ? (
        <div id="body">
          <Sidebar
            proxyAddr={proxyAddr}
            calls={calls}
            visibleCalls={visibleCalls}
            selectedID={selectedID}
            filterText={filterText}
            onFilterChange={setFilterText}
            onSelect={selectCall}
          />
          <DetailPane call={selectedCall} />
        </div>
      ) : (
        <FrameInspector />
      )}
    </div>
  )
}
