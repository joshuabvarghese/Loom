// Package webui serves the Loom Web Inspector.
//
// It exposes:
//
//	GET  /              — single-page HTML inspector
//	GET  /api/calls     — JSON array of all recorded calls (newest first)
//	GET  /api/calls/:id — single call record by ID
//	GET  /api/stream    — SSE stream of new calls in real-time
//	POST /api/replay/:id — replay a recorded call through the proxy
package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
)

// ReplayFunc replays a recorded call and returns a status string or error.
type ReplayFunc func(call *recpkg.CallRecord) (string, error)

// Server is the Web Inspector HTTP server.
type Server struct {
	rec          *recpkg.Recorder
	replay       ReplayFunc
	proxyAddr    string
	backendTLS   bool
}

// NewWithOptions creates a Server.
//   - rec        — the recorder to read calls from and subscribe to
//   - replayFn   — called when the client requests a replay (may be nil)
//   - proxyAddr  — address of the proxy, shown in the UI (e.g. "localhost:9999")
//   - backendTLS — whether the proxy is talking TLS to the backend
func NewWithOptions(rec *recpkg.Recorder, replayFn ReplayFunc, proxyAddr string, backendTLS bool) *Server {
	return &Server{
		rec:        rec,
		replay:     replayFn,
		proxyAddr:  proxyAddr,
		backendTLS: backendTLS,
	}
}

// Handler returns the http.Handler for the inspector.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/calls", s.handleCalls)
	mux.HandleFunc("/api/calls/", s.handleCallByID)
	mux.HandleFunc("/api/stream", s.handleSSE)
	mux.HandleFunc("/api/replay/", s.handleReplay)
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

// ── Route handlers ────────────────────────────────────────────────────────────

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, inspectorHTML(s.proxyAddr))
}

func (s *Server) handleCalls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	calls := s.rec.Store.All()
	if err := json.NewEncoder(w).Encode(calls); err != nil {
		http.Error(w, "encoding calls", http.StatusInternalServerError)
	}
}

func (s *Server) handleCallByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/calls/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	call, ok := s.rec.Store.ByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(call) //nolint:errcheck
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// Send a heartbeat immediately so the browser knows we're alive
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ch := s.rec.Hub.Subscribe()
	defer s.rec.Hub.Unsubscribe(ch)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case call, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(call)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if s.replay == nil {
		http.Error(w, "replay not configured", http.StatusNotImplemented)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/replay/")
	call, ok := s.rec.Store.ByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	result, err := s.replay(call)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "replayed", "id": result}) //nolint:errcheck
}

// ── Embedded HTML UI ──────────────────────────────────────────────────────────

func inspectorHTML(proxyAddr string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Loom — gRPC Inspector</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #181c27;
    --border: #2a2e3d;
    --accent: #7c6af7;
    --accent2: #4fc3f7;
    --ok: #4caf50;
    --err: #ef5350;
    --text: #e2e8f0;
    --muted: #64748b;
    --code-bg: #0a0c14;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'SF Mono', 'Fira Code', monospace; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; font-size: 13px; }

  header {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 16px; background: var(--surface);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  header h1 { font-size: 15px; color: var(--accent); letter-spacing: 0.05em; }
  .proxy-addr { color: var(--muted); font-size: 11px; }
  .badge { font-size: 10px; padding: 2px 7px; border-radius: 10px; background: var(--border); color: var(--muted); }
  .badge.live { background: #1a2e1a; color: var(--ok); }
  .spacer { flex: 1; }
  .btn {
    padding: 4px 12px; border-radius: 5px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text); cursor: pointer; font-size: 12px;
    font-family: inherit;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }

  .layout { display: flex; flex: 1; overflow: hidden; }

  /* ── Call list ── */
  .call-list {
    width: 340px; min-width: 220px; flex-shrink: 0;
    border-right: 1px solid var(--border);
    overflow-y: auto; display: flex; flex-direction: column;
  }
  .call-list-header {
    padding: 8px 12px; font-size: 11px; color: var(--muted);
    border-bottom: 1px solid var(--border); flex-shrink: 0;
    display: flex; align-items: center; gap: 8px;
  }
  #filterInput {
    flex: 1; background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 3px 8px; color: var(--text);
    font-size: 11px; font-family: inherit; outline: none;
  }
  #filterInput:focus { border-color: var(--accent); }
  .call-item {
    padding: 8px 12px; border-bottom: 1px solid var(--border);
    cursor: pointer; display: flex; flex-direction: column; gap: 3px;
    transition: background 0.1s;
  }
  .call-item:hover { background: var(--surface); }
  .call-item.selected { background: #1e1b3a; border-left: 2px solid var(--accent); }
  .call-item .method-name { font-size: 11px; color: var(--accent2); word-break: break-all; }
  .call-item .call-meta { display: flex; gap: 8px; align-items: center; }
  .status-badge {
    font-size: 10px; padding: 1px 6px; border-radius: 3px;
    font-weight: 600; letter-spacing: 0.03em;
  }
  .status-ok { background: #1a3320; color: var(--ok); }
  .status-err { background: #3a1a1a; color: var(--err); }
  .call-time { font-size: 10px; color: var(--muted); }
  .call-dur { font-size: 10px; color: var(--muted); margin-left: auto; }
  .empty-state { padding: 32px 16px; text-align: center; color: var(--muted); line-height: 1.8; }
  .empty-state .loom-logo { font-size: 22px; margin-bottom: 8px; }

  /* ── Detail pane ── */
  .detail { flex: 1; overflow-y: auto; display: flex; flex-direction: column; }
  .no-selection { flex: 1; display: flex; align-items: center; justify-content: center; color: var(--muted); }

  .detail-header {
    padding: 10px 16px; background: var(--surface);
    border-bottom: 1px solid var(--border); flex-shrink: 0;
    display: flex; align-items: center; gap: 10px;
  }
  .detail-method { font-size: 13px; color: var(--accent2); flex: 1; word-break: break-all; }
  .replay-btn {
    padding: 3px 10px; border-radius: 4px; border: 1px solid var(--accent);
    background: transparent; color: var(--accent); cursor: pointer;
    font-size: 11px; font-family: inherit;
  }
  .replay-btn:hover { background: var(--accent); color: #fff; }

  .detail-body { flex: 1; padding: 14px 16px; display: flex; flex-direction: column; gap: 14px; }

  .section-label {
    font-size: 10px; color: var(--muted); text-transform: uppercase;
    letter-spacing: 0.1em; margin-bottom: 6px;
  }
  .code-block {
    background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px; overflow-x: auto;
    white-space: pre; font-size: 12px; line-height: 1.6;
    color: #a5d6ff; max-height: 320px; overflow-y: auto;
  }
  .grpcurl-block {
    background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px;
    display: flex; align-items: flex-start; gap: 8px;
  }
  .grpcurl-cmd { flex: 1; white-space: pre-wrap; word-break: break-all; color: #a5d6ff; font-size: 12px; }
  .copy-btn {
    padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);
    background: var(--surface); color: var(--muted); cursor: pointer;
    font-size: 11px; font-family: inherit; flex-shrink: 0;
  }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }

  .mutated-badge {
    font-size: 10px; padding: 1px 6px; border-radius: 3px;
    background: #2a1f00; color: #ffa726; margin-left: 6px;
  }

  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .tab {
    padding: 6px 14px; font-size: 11px; color: var(--muted); cursor: pointer;
    border-bottom: 2px solid transparent; margin-bottom: -1px;
  }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab:hover { color: var(--text); }
</style>
</head>
<body>

<header>
  <h1>🧵 Loom</h1>
  <span class="proxy-addr">` + proxyAddr + `</span>
  <span class="badge live" id="connBadge">● live</span>
  <span class="spacer"></span>
  <button class="btn" onclick="clearCalls()">Clear</button>
</header>

<div class="layout">
  <!-- ── Call list ── -->
  <div class="call-list">
    <div class="call-list-header">
      <input id="filterInput" placeholder="filter methods…" oninput="applyFilter()">
      <span id="callCount" style="flex-shrink:0">0 calls</span>
    </div>
    <div id="callList">
      <div class="empty-state">
        <div class="loom-logo">🧵</div>
        Waiting for gRPC calls…<br>
        <span style="font-size:11px">Point your client at ` + proxyAddr + `</span>
      </div>
    </div>
  </div>

  <!-- ── Detail pane ── -->
  <div class="detail" id="detailPane">
    <div class="no-selection">← Select a call to inspect</div>
  </div>
</div>

<script>
const proxyAddr = ` + "`" + proxyAddr + "`" + `;
let calls = [];
let selectedID = null;
let filter = '';

// ── Bootstrap: load history + open SSE ────────────────────────────────────────
async function init() {
  try {
    const r = await fetch('/api/calls');
    const hist = await r.json();
    if (Array.isArray(hist)) {
      calls = hist;
      renderList();
    }
  } catch(e) { console.warn('history load failed', e); }
  openSSE();
}

function openSSE() {
  const es = new EventSource('/api/stream');
  es.onopen = () => { document.getElementById('connBadge').textContent = '● live'; document.getElementById('connBadge').className = 'badge live'; };
  es.onmessage = e => {
    try {
      const call = JSON.parse(e.data);
      // prepend (newest first)
      calls.unshift(call);
      renderList();
      if (!selectedID) selectCall(call.id);
    } catch(_) {}
  };
  es.onerror = () => {
    document.getElementById('connBadge').textContent = '○ reconnecting…';
    document.getElementById('connBadge').className = 'badge';
    setTimeout(openSSE, 3000);
    es.close();
  };
}

// ── Rendering ─────────────────────────────────────────────────────────────────
function applyFilter() {
  filter = document.getElementById('filterInput').value.toLowerCase();
  renderList();
}

function renderList() {
  const list = document.getElementById('callList');
  const visible = calls.filter(c => !filter || c.method.toLowerCase().includes(filter));
  document.getElementById('callCount').textContent = visible.length + ' calls';

  if (visible.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="loom-logo">🧵</div>Waiting for gRPC calls…<br><span style="font-size:11px">Point your client at ' + proxyAddr + '</span></div>';
    return;
  }
  list.innerHTML = visible.map(c => {
    const isOK = c.statusCode === '0' || c.statusCode === '';
    const statusClass = isOK ? 'status-ok' : 'status-err';
    const statusLabel = c.statusName || (isOK ? 'OK' : 'ERR');
    const shortMethod = c.method.split('/').pop() || c.method;
    const t = new Date(c.timestamp).toLocaleTimeString();
    const mut = c.mutated ? '<span class="mutated-badge">mutated</span>' : '';
    return '<div class="call-item' + (c.id === selectedID ? ' selected' : '') + '" onclick="selectCall(\'' + c.id + '\')" id="item-' + c.id + '">' +
      '<div class="method-name">' + escHtml(shortMethod) + mut + '</div>' +
      '<div class="call-meta">' +
        '<span class="status-badge ' + statusClass + '">' + escHtml(statusLabel) + '</span>' +
        '<span class="call-time">' + t + '</span>' +
        '<span class="call-dur">' + c.durationMs.toFixed(1) + 'ms</span>' +
      '</div>' +
    '</div>';
  }).join('');
}

function selectCall(id) {
  selectedID = id;
  // Update selection highlight
  document.querySelectorAll('.call-item').forEach(el => el.classList.remove('selected'));
  const item = document.getElementById('item-' + id);
  if (item) item.classList.add('selected');

  const call = calls.find(c => c.id === id);
  if (!call) return;
  renderDetail(call);
}

function renderDetail(call) {
  const pane = document.getElementById('detailPane');
  const isOK = call.statusCode === '0' || call.statusCode === '';
  const statusClass = isOK ? 'status-ok' : 'status-err';
  const statusLabel = call.statusName || (isOK ? 'OK' : 'ERR');
  const mut = call.mutated ? '<span class="mutated-badge">mutated</span>' : '';

  const reqJSON = (call.request && call.request.length > 0 && call.request[0].json)
    ? call.request[0].json : '(no request body)';
  const respJSON = (call.response && call.response.length > 0 && call.response[0].json)
    ? call.response[0].json : '(no response body)';

  pane.innerHTML =
    '<div class="detail-header">' +
      '<div class="detail-method">' + escHtml(call.method) + mut + '</div>' +
      '<span class="status-badge ' + statusClass + '">' + escHtml(statusLabel) + '</span>' +
      '<span style="color:var(--muted);font-size:11px;margin-left:8px">' + call.durationMs.toFixed(2) + 'ms</span>' +
      (call.request && call.request.length ? '<button class="replay-btn" onclick="replayCall(\'' + call.id + '\')">↩ Replay</button>' : '') +
    '</div>' +

    '<div class="detail-body">' +

      // Request
      '<div>' +
        '<div class="section-label">Request</div>' +
        '<div class="code-block" id="reqBlock">' + escHtml(reqJSON) + '</div>' +
      '</div>' +

      // Response
      '<div>' +
        '<div class="section-label">Response</div>' +
        '<div class="code-block">' + escHtml(respJSON) + '</div>' +
      '</div>' +

      // grpcurl
      (call.grpcurlCmd ? (
        '<div>' +
          '<div class="section-label">grpcurl</div>' +
          '<div class="grpcurl-block">' +
            '<span class="grpcurl-cmd" id="grpcurlCmd">' + escHtml(call.grpcurlCmd) + '</span>' +
            '<button class="copy-btn" onclick="copyGrpcurl()">copy</button>' +
          '</div>' +
        '</div>'
      ) : '') +

      // Error
      (call.error ? (
        '<div>' +
          '<div class="section-label">Error</div>' +
          '<div class="code-block" style="color:var(--err)">' + escHtml(call.error) + '</div>' +
        '</div>'
      ) : '') +

    '</div>';
}

async function replayCall(id) {
  try {
    const r = await fetch('/api/replay/' + id, {method: 'POST'});
    const data = await r.json();
    if (data.error) alert('Replay error: ' + data.error);
  } catch(e) { alert('Replay failed: ' + e); }
}

function copyGrpcurl() {
  const el = document.getElementById('grpcurlCmd');
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    const btn = el.nextElementSibling;
    if (btn) { btn.textContent = 'copied!'; setTimeout(() => btn.textContent = 'copy', 1500); }
  });
}

function clearCalls() {
  calls = [];
  selectedID = null;
  renderList();
  document.getElementById('detailPane').innerHTML = '<div class="no-selection">← Select a call to inspect</div>';
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

init();
</script>
</body>
</html>`
}
