interface TopBarProps {
  proxyAddr: string
  connected: boolean
  total: number
  ok: number
  err: number
  onClear: () => void
}

export default function TopBar({ proxyAddr, connected, total, ok, err, onClear }: TopBarProps) {
  return (
    <div id="topbar">
      <div className="logo">
        <div className="logo-icon">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 3h8M2 6h6M2 9h4" stroke="white" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </div>
        loom
      </div>

      <div className="topbar-sep" />

      <div className="proxy-info">
        <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
          <circle cx="5.5" cy="5.5" r="4.5" stroke="currentColor" strokeWidth="1" />
          <path d="M5.5 1v9M1 5.5h9" stroke="currentColor" strokeWidth="1" />
        </svg>
        <code>{proxyAddr}</code>
      </div>

      <div id="liveChip" className={connected ? 'connected' : ''}>
        <div className="dot" />
        <span>{connected ? 'live' : 'reconnecting…'}</span>
      </div>

      <div className="spacer" />

      <div className="topbar-stat">
        {total} <span>calls</span>
      </div>
      <div className="topbar-stat" style={{ color: 'var(--green)' }}>
        {ok} <span style={{ color: 'var(--text3)' }}>ok</span>
      </div>
      <div className="topbar-stat" style={{ color: 'var(--red)' }}>
        {err} <span style={{ color: 'var(--text3)' }}>err</span>
      </div>

      <div className="topbar-sep" />

      <button className="icon-btn" title="Clear calls" onClick={onClear}>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
          <path
            d="M2 3.5h9M5 3.5V2.5h3v1M3.5 3.5l.5 7h5l.5-7"
            stroke="currentColor"
            strokeWidth="1.1"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </button>
    </div>
  )
}
