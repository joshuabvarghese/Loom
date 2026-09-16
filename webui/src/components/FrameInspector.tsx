import { useFrameStream } from '../hooks/useFrameStream'
import Http2FrameTimeline from './Http2FrameTimeline'
import FrameLogList from './FrameLogList'
import FrameDetailPane from './FrameDetailPane'

export default function FrameInspector() {
  const { frames, connected, selectedSeq, setSelectedSeq, selectedFrame, clearFrames } =
    useFrameStream()

  return (
    <div id="frame-inspector">
      <div className="frame-inspector-toolbar">
        <div className={`live-chip-inline ${connected ? 'connected' : ''}`}>
          <div className="dot" />
          <span>{connected ? 'live' : 'reconnecting…'}</span>
        </div>
        <span className="frame-count">{frames.length} frames</span>
        <div className="spacer" />
        <button className="icon-btn" title="Clear frames" onClick={clearFrames}>
          Clear
        </button>
      </div>

      <div className="frame-timeline-wrap">
        <Http2FrameTimeline frames={frames} selectedSeq={selectedSeq} onSelect={setSelectedSeq} />
      </div>

      <div className="frame-lower">
        <FrameLogList frames={frames} selectedSeq={selectedSeq} onSelect={setSelectedSeq} />
        <FrameDetailPane frame={selectedFrame} />
      </div>
    </div>
  )
}
