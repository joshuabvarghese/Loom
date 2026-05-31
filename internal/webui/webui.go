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
	rec        *recpkg.Recorder
	replay     ReplayFunc
	proxyAddr  string
	backendTLS bool
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
<title>Loom</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=GeistMono:wght@300;400;500;600&family=Geist:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:        #0c0e12;
  --panel:     #10131a;
  --card:      #13171f;
  --border:    #1e2330;
  --border2:   #252b3b;
  --accent:    #3b7eff;
  --accent-dim:#1a3a7a;
  --green:     #22c55e;
  --green-dim: #052e16;
  --red:       #f43f5e;
  --red-dim:   #2d0a12;
  --amber:     #f59e0b;
  --amber-dim: #2d1f00;
  --cyan:      #22d3ee;
  --text:      #e4e8f0;
  --text2:     #8892a4;
  --text3:     #4b5568;
  --mono:      'GeistMono', 'Fira Code', monospace;
  --sans:      'Geist', system-ui, sans-serif;
  --radius:    6px;
  --header-h:  44px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 13px;
  line-height: 1.5;
  overflow: hidden;
}

/* ── Scrollbar ────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover { background: var(--text3); }

/* ── Layout ───────────────────────────────────────────────── */
#app { display: flex; flex-direction: column; height: 100vh; }

/* ── Topbar ───────────────────────────────────────────────── */
#topbar {
  height: var(--header-h);
  display: flex;
  align-items: center;
  gap: 0;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  padding: 0 16px;
  gap: 12px;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: var(--mono);
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: -0.02em;
  user-select: none;
}

.logo-icon {
  width: 22px;
  height: 22px;
  background: var(--accent);
  border-radius: 5px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  flex-shrink: 0;
}

.topbar-sep {
  width: 1px;
  height: 20px;
  background: var(--border);
  flex-shrink: 0;
}

.proxy-info {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
}

.proxy-info code {
  color: var(--cyan);
  background: rgba(34,211,238,0.07);
  padding: 1px 6px;
  border-radius: 4px;
}

#liveChip {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  font-family: var(--mono);
  padding: 3px 9px;
  border-radius: 99px;
  border: 1px solid var(--border2);
  color: var(--text3);
  transition: all 0.2s;
}
#liveChip.connected {
  color: var(--green);
  border-color: rgba(34,197,94,0.25);
  background: rgba(34,197,94,0.05);
}
#liveChip.connected .dot { background: var(--green); animation: pulse 2s infinite; }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text3); flex-shrink: 0; }

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.spacer { flex: 1; }

.topbar-stat {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
}
.topbar-stat span { color: var(--text2); }

.icon-btn {
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius);
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text3);
  cursor: pointer;
  transition: all 0.15s;
  font-size: 13px;
}
.icon-btn:hover { background: var(--card); color: var(--text); border-color: var(--border2); }

/* ── Body ─────────────────────────────────────────────────── */
#body { display: flex; flex: 1; overflow: hidden; }

/* ── Sidebar ──────────────────────────────────────────────── */
#sidebar {
  width: 320px;
  min-width: 240px;
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--border);
  flex-shrink: 0;
  background: var(--panel);
}

.sidebar-toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.search-wrap {
  flex: 1;
  position: relative;
  display: flex;
  align-items: center;
}

.search-icon {
  position: absolute;
  left: 8px;
  color: var(--text3);
  font-size: 11px;
  pointer-events: none;
}

#searchInput {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 5px 8px 5px 26px;
  color: var(--text);
  font-size: 12px;
  font-family: var(--mono);
  outline: none;
  transition: border-color 0.15s;
}
#searchInput:focus { border-color: var(--accent); }
#searchInput::placeholder { color: var(--text3); }

#callList {
  flex: 1;
  overflow-y: auto;
}

/* ── Call item ────────────────────────────────────────────── */
.call-item {
  display: flex;
  align-items: stretch;
  gap: 0;
  padding: 0;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.1s;
  position: relative;
}
.call-item:hover { background: rgba(255,255,255,0.02); }
.call-item.selected { background: rgba(59,126,255,0.06); }
.call-item.selected::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 2px;
  background: var(--accent);
}

.call-status-bar {
  width: 3px;
  flex-shrink: 0;
}
.call-status-bar.ok { background: var(--green); }
.call-status-bar.err { background: var(--red); }

.call-inner {
  flex: 1;
  padding: 9px 12px;
  min-width: 0;
}

.call-method {
  font-family: var(--mono);
  font-size: 11.5px;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 4px;
}
.call-method .pkg { color: var(--text3); }
.call-method .svc { color: var(--text2); }
.call-method .rpc { color: var(--cyan); }

.call-foot {
  display: flex;
  align-items: center;
  gap: 6px;
}

.chip {
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 500;
  padding: 1px 6px;
  border-radius: 4px;
  letter-spacing: 0.02em;
}
.chip-ok   { background: var(--green-dim); color: var(--green); }
.chip-err  { background: var(--red-dim);   color: var(--red); }
.chip-mut  { background: var(--amber-dim); color: var(--amber); }
.chip-kind { background: rgba(255,255,255,0.05); color: var(--text3); }

.call-time { font-family: var(--mono); font-size: 10px; color: var(--text3); }
.call-dur  { font-family: var(--mono); font-size: 10px; color: var(--text3); margin-left: auto; }

/* ── Empty state ──────────────────────────────────────────── */
.empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 10px;
  color: var(--text3);
  padding: 40px 20px;
  text-align: center;
}
.empty-glyph {
  font-size: 32px;
  opacity: 0.3;
  font-family: var(--mono);
}
.empty p { font-size: 12px; line-height: 1.8; }
.empty code { font-family: var(--mono); color: var(--cyan); font-size: 11px; }

/* ── Detail pane ──────────────────────────────────────────── */
#detail {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg);
}

.no-selection {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--text3);
  font-family: var(--mono);
  font-size: 12px;
}
.no-selection .arrow { font-size: 24px; opacity: 0.2; }

/* ── Detail header ────────────────────────────────────────── */
#detailHeader {
  padding: 12px 18px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
  background: var(--panel);
}

.detail-method {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--text);
  margin-bottom: 8px;
  word-break: break-all;
}
.detail-method .pkg { color: var(--text3); }
.detail-method .svc { color: var(--text2); }
.detail-method .rpc { color: var(--cyan); font-weight: 500; }

.detail-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
}
.meta-item .val { color: var(--text2); }

.replay-btn {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border-radius: var(--radius);
  border: 1px solid var(--border2);
  background: var(--card);
  color: var(--text2);
  font-size: 11px;
  font-family: var(--mono);
  cursor: pointer;
  transition: all 0.15s;
}
.replay-btn:hover { border-color: var(--accent); color: var(--accent); background: rgba(59,126,255,0.07); }
.replay-btn:active { transform: scale(0.97); }
.replay-btn svg { flex-shrink: 0; }

/* ── Tabs ─────────────────────────────────────────────────── */
#tabs {
  display: flex;
  border-bottom: 1px solid var(--border);
  background: var(--panel);
  flex-shrink: 0;
  padding: 0 18px;
  gap: 4px;
}

.tab {
  padding: 8px 14px;
  font-size: 12px;
  font-family: var(--mono);
  color: var(--text3);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  margin-bottom: -1px;
  transition: color 0.15s;
  white-space: nowrap;
}
.tab:hover { color: var(--text2); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }

/* ── Tab content ──────────────────────────────────────────── */
#tabContent {
  flex: 1;
  overflow-y: auto;
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-label {
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 7px;
}

.code-wrap {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

.code-toolbar {
  display: flex;
  align-items: center;
  padding: 6px 12px;
  border-bottom: 1px solid var(--border);
  gap: 8px;
}

.code-label {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  flex: 1;
}

.copy-btn {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 2px 8px;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text3);
  font-size: 10px;
  font-family: var(--mono);
  cursor: pointer;
  transition: all 0.15s;
}
.copy-btn:hover { border-color: var(--border2); color: var(--text2); }
.copy-btn.copied { color: var(--green); border-color: rgba(34,197,94,0.3); }

pre.code {
  padding: 12px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.7;
  color: var(--text2);
  overflow-x: auto;
  white-space: pre;
  max-height: 380px;
  overflow-y: auto;
}

/* JSON coloring */
.json-key    { color: #93c5fd; }
.json-str    { color: #86efac; }
.json-num    { color: #fca5a5; }
.json-bool   { color: #fdba74; }
.json-null   { color: var(--text3); }
.json-punc   { color: var(--text3); }

.grpcurl-wrap {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

pre.grpcurl {
  padding: 12px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--text2);
}

.cmd-flag  { color: #93c5fd; }
.cmd-value { color: #86efac; }
.cmd-bin   { color: var(--cyan); font-weight: 500; }
.cmd-method{ color: #fdba74; }

/* ── Frames list (streaming) ──────────────────────────────── */
.frames-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.frame-item {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  background: var(--panel);
}

.frame-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border-bottom: 1px solid var(--border);
  background: var(--card);
  cursor: pointer;
  user-select: none;
}

.frame-idx {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  background: var(--border);
  padding: 1px 6px;
  border-radius: 4px;
}

.frame-chevron {
  margin-left: auto;
  color: var(--text3);
  font-size: 10px;
  transition: transform 0.15s;
}
.frame-item.collapsed .frame-chevron { transform: rotate(-90deg); }
.frame-item.collapsed pre.code { display: none; }

/* ── Headers tab ──────────────────────────────────────────── */
.kv-table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--mono);
  font-size: 12px;
}
.kv-table tr { border-bottom: 1px solid var(--border); }
.kv-table tr:last-child { border-bottom: none; }
.kv-table td {
  padding: 7px 10px;
  vertical-align: top;
}
.kv-table td:first-child {
  color: var(--text3);
  width: 40%;
  white-space: nowrap;
}
.kv-table td:last-child {
  color: var(--text2);
  word-break: break-all;
}
.kv-wrap {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

/* ── Error banner ─────────────────────────────────────────── */
.error-banner {
  display: flex;
  gap: 10px;
  padding: 10px 14px;
  background: var(--red-dim);
  border: 1px solid rgba(244,63,94,0.2);
  border-radius: var(--radius);
  font-family: var(--mono);
  font-size: 12px;
  color: var(--red);
  align-items: flex-start;
}

/* ── Sidebar status bar ───────────────────────────────────── */
#sidebarFooter {
  border-top: 1px solid var(--border);
  padding: 6px 12px;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  display: flex;
  gap: 12px;
  flex-shrink: 0;
}
#sidebarFooter span { color: var(--text2); }
</style>
</head>
<body>
<div id="app">

  <!-- ── Topbar ── -->
  <div id="topbar">
    <div class="logo">
      <div class="logo-icon">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M2 3h8M2 6h6M2 9h4" stroke="white" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      </div>
      loom
    </div>

    <div class="topbar-sep"></div>

    <div class="proxy-info">
      <svg width="11" height="11" viewBox="0 0 11 11" fill="none"><circle cx="5.5" cy="5.5" r="4.5" stroke="currentColor" stroke-width="1"/><path d="M5.5 1v9M1 5.5h9" stroke="currentColor" stroke-width="1"/></svg>
      <code id="proxyAddrDisplay">` + proxyAddr + `</code>
    </div>

    <div id="liveChip">
      <div class="dot"></div>
      <span id="connLabel">connecting</span>
    </div>

    <div class="spacer"></div>

    <div class="topbar-stat" id="statTotal">0 <span>calls</span></div>
    <div class="topbar-stat" id="statOK" style="color:var(--green)">0 <span style="color:var(--text3)">ok</span></div>
    <div class="topbar-stat" id="statErr" style="color:var(--red)">0 <span style="color:var(--text3)">err</span></div>

    <div class="topbar-sep"></div>

    <button class="icon-btn" title="Clear calls" onclick="clearCalls()">
      <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 3.5h9M5 3.5V2.5h3v1M3.5 3.5l.5 7h5l.5-7" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>
  </div>

  <!-- ── Body ── -->
  <div id="body">

    <!-- ── Sidebar ── -->
    <div id="sidebar">
      <div class="sidebar-toolbar">
        <div class="search-wrap">
          <svg class="search-icon" width="11" height="11" viewBox="0 0 11 11" fill="none"><circle cx="4.5" cy="4.5" r="3.5" stroke="currentColor" stroke-width="1.1"/><path d="M7.5 7.5L10 10" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/></svg>
          <input id="searchInput" placeholder="Filter methods…" oninput="applyFilter()">
        </div>
      </div>

      <div id="callList">
        <div class="empty" id="emptyState">
          <div class="empty-glyph">⌀</div>
          <p>No calls yet.<br>Point your client at<br><code>` + proxyAddr + `</code></p>
        </div>
      </div>

      <div id="sidebarFooter">
        <div id="footTotal">total <span id="footTotalN">0</span></div>
        <div id="footFiltered" style="display:none">showing <span id="footFilteredN">0</span></div>
      </div>
    </div>

    <!-- ── Detail ── -->
    <div id="detail">
      <div class="no-selection" id="noSelection">
        <div class="arrow">←</div>
        <div>Select a call</div>
      </div>
    </div>
  </div>
</div>

<script>
// ── State ──────────────────────────────────────────────────
const PROXY = '` + proxyAddr + `';
let calls = [];
let selectedID = null;
let filterText = '';
let activeTab = 'request';
let es = null;

// ── Bootstrap ──────────────────────────────────────────────
async function init() {
  document.querySelectorAll('[id="proxyAddrDisplay"], .empty p code').forEach(el => {
    el.textContent = el.textContent.replace(/` + proxyAddr + `/g, PROXY);
  });
  try {
    const r = await fetch('/api/calls');
    const hist = await r.json();
    if (Array.isArray(hist)) { calls = hist; renderList(); updateStats(); }
  } catch(e) { console.warn('history load:', e); }
  connectSSE();
}

// ── SSE ────────────────────────────────────────────────────
function connectSSE() {
  if (es) es.close();
  es = new EventSource('/api/stream');
  es.onopen = () => setConnState(true);
  es.onmessage = e => {
    try {
      const call = JSON.parse(e.data);
      calls.unshift(call);
      renderList();
      updateStats();
      if (!selectedID) selectCall(call.id);
    } catch(_) {}
  };
  es.onerror = () => {
    setConnState(false);
    setTimeout(connectSSE, 3000);
    es.close(); es = null;
  };
}

function setConnState(on) {
  const chip = document.getElementById('liveChip');
  const label = document.getElementById('connLabel');
  chip.className = on ? 'connected' : '';
  label.textContent = on ? 'live' : 'reconnecting…';
}

// ── Rendering: list ────────────────────────────────────────
function applyFilter() {
  filterText = document.getElementById('searchInput').value.toLowerCase().trim();
  renderList();
}

function visible() {
  return filterText
    ? calls.filter(c => c.method.toLowerCase().includes(filterText))
    : calls;
}

function renderList() {
  const list = document.getElementById('callList');
  const items = visible();

  // Footer
  const footFiltered = document.getElementById('footFiltered');
  document.getElementById('footTotalN').textContent = calls.length;
  if (filterText) {
    footFiltered.style.display = '';
    document.getElementById('footFilteredN').textContent = items.length;
  } else {
    footFiltered.style.display = 'none';
  }

  if (items.length === 0) {
    list.innerHTML = calls.length === 0
      ? '<div class="empty" id="emptyState"><div class="empty-glyph">⌀</div><p>No calls yet.<br>Point your client at<br><code>' + escHtml(PROXY) + '</code></p></div>'
      : '<div class="empty"><div class="empty-glyph">∅</div><p>No matches for<br><code>' + escHtml(filterText) + '</code></p></div>';
    return;
  }

  list.innerHTML = items.map(c => {
    const ok = isOK(c);
    const parts = parseMethod(c.method);
    const t = new Date(c.timestamp).toLocaleTimeString('en', {hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit'});
    const sel = c.id === selectedID ? ' selected' : '';
    const statusChip = ok
      ? '<span class="chip chip-ok">' + escHtml(c.statusName || 'OK') + '</span>'
      : '<span class="chip chip-err">' + escHtml(c.statusName || 'ERR') + '</span>';
    const mutChip = c.mutated ? '<span class="chip chip-mut">mut</span>' : '';
    const kindChip = c.streamKind && c.streamKind !== 'unary'
      ? '<span class="chip chip-kind">' + escHtml(streamLabel(c.streamKind)) + '</span>'
      : '';
    return (
      '<div class="call-item' + sel + '" id="ci-' + c.id + '" onclick="selectCall(\'' + c.id + '\')">' +
        '<div class="call-status-bar ' + (ok ? 'ok' : 'err') + '"></div>' +
        '<div class="call-inner">' +
          '<div class="call-method">' +
            '<span class="pkg">' + escHtml(parts.pkg) + (parts.pkg ? '.' : '') + '</span>' +
            '<span class="svc">' + escHtml(parts.svc) + (parts.svc ? '/' : '') + '</span>' +
            '<span class="rpc">' + escHtml(parts.rpc) + '</span>' +
          '</div>' +
          '<div class="call-foot">' +
            statusChip + mutChip + kindChip +
            '<span class="call-time">' + t + '</span>' +
            '<span class="call-dur">' + fmtDur(c.durationMs) + '</span>' +
          '</div>' +
        '</div>' +
      '</div>'
    );
  }).join('');
}

// ── Rendering: detail ──────────────────────────────────────
function selectCall(id) {
  selectedID = id;
  document.querySelectorAll('.call-item').forEach(el => el.classList.remove('selected'));
  const el = document.getElementById('ci-' + id);
  if (el) { el.classList.add('selected'); el.scrollIntoView({block:'nearest'}); }
  const call = calls.find(c => c.id === id);
  if (!call) return;
  activeTab = 'request';
  renderDetail(call);
}

function renderDetail(call) {
  const detail = document.getElementById('detail');
  const parts = parseMethod(call.method);
  const ok = isOK(call);

  const tabs = [
    {id:'request',  label:'Request'},
    {id:'response', label:'Response'},
    {id:'grpcurl',  label:'grpcurl'},
    {id:'info',     label:'Info'},
  ];

  detail.innerHTML =
    // Header
    '<div id="detailHeader">' +
      '<div class="detail-method">' +
        '<span class="pkg">' + escHtml(parts.pkg) + (parts.pkg ? '.' : '') + '</span>' +
        '<span class="svc">' + escHtml(parts.svc) + (parts.svc ? '/' : '') + '</span>' +
        '<span class="rpc">' + escHtml(parts.rpc) + '</span>' +
      '</div>' +
      '<div class="detail-meta">' +
        (ok
          ? '<span class="chip chip-ok">' + escHtml(call.statusName || 'OK') + '</span>'
          : '<span class="chip chip-err">' + escHtml(call.statusName || 'ERR') + '</span>') +
        (call.mutated ? '<span class="chip chip-mut">mutated</span>' : '') +
        '<div class="meta-item"><span>duration</span><span class="val">' + fmtDur(call.durationMs) + '</span></div>' +
        '<div class="meta-item"><span>type</span><span class="val">' + escHtml(streamLabel(call.streamKind || 'unary')) + '</span></div>' +
        '<div class="meta-item"><span>id</span><span class="val">' + escHtml(call.id.split('-')[0]) + '</span></div>' +
        (call.request && call.request.length
          ? '<button class="replay-btn" onclick="replayCall(\'' + call.id + '\')">' +
              '<svg width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M2 9V2l7 3.5L2 9z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/></svg>' +
              'Replay' +
            '</button>'
          : '') +
      '</div>' +
    '</div>' +

    // Tabs
    '<div id="tabs">' +
      tabs.map(t =>
        '<div class="tab' + (t.id === activeTab ? ' active' : '') + '" onclick="switchTab(\'' + call.id + '\',\'' + t.id + '\')">' + t.label + '</div>'
      ).join('') +
    '</div>' +

    // Tab content
    '<div id="tabContent"></div>';

  renderTab(call);
}

function switchTab(id, tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(el => {
    el.classList.toggle('active', el.textContent.toLowerCase() === tab || el.getAttribute('onclick') && el.getAttribute('onclick').includes("'" + tab + "'"));
  });
  // Re-match by onclick
  document.querySelectorAll('.tab').forEach(el => {
    const m = el.getAttribute('onclick') || '';
    el.classList.toggle('active', m.includes("'" + tab + "'"));
  });
  const call = calls.find(c => c.id === id);
  if (call) renderTab(call);
}

function renderTab(call) {
  const content = document.getElementById('tabContent');
  if (!content) return;

  if (activeTab === 'request') {
    const frames = call.request || [];
    content.innerHTML = frames.length === 0
      ? '<div style="color:var(--text3);font-family:var(--mono);font-size:12px">(no request frames)</div>'
      : renderFrames(frames, 'req');
  }

  else if (activeTab === 'response') {
    const frames = call.response || [];
    let html = frames.length === 0
      ? '<div style="color:var(--text3);font-family:var(--mono);font-size:12px">(no response frames)</div>'
      : renderFrames(frames, 'res');
    if (call.grpcMessage) {
      html += '<div class="error-banner">gRPC message: ' + escHtml(call.grpcMessage) + '</div>';
    }
    if (call.error) {
      html += '<div class="error-banner">' + escHtml(call.error) + '</div>';
    }
    content.innerHTML = html;
  }

  else if (activeTab === 'grpcurl') {
    if (!call.grpcurlCmd) {
      content.innerHTML = '<div style="color:var(--text3);font-family:var(--mono);font-size:12px">(no grpcurl available for this call)</div>';
    } else {
      content.innerHTML =
        '<div>' +
          '<div class="section-label">Replay command</div>' +
          '<div class="grpcurl-wrap">' +
            '<div class="code-toolbar">' +
              '<span class="code-label">grpcurl</span>' +
              '<button class="copy-btn" id="gcCopy" onclick="copyText(\'' + escHtml(call.id) + '-gcmd\', \'gcCopy\')">copy</button>' +
            '</div>' +
            '<pre class="grpcurl" id="' + call.id + '-gcmd">' + colorGrpcurl(call.grpcurlCmd) + '</pre>' +
          '</div>' +
        '</div>';
    }
  }

  else if (activeTab === 'info') {
    const rows = [
      ['id',        call.id],
      ['method',    call.method],
      ['type',      streamLabel(call.streamKind || 'unary')],
      ['status code', call.statusCode || '0'],
      ['status',    call.statusName || 'OK'],
      ['duration',  fmtDur(call.durationMs)],
      ['timestamp', new Date(call.timestamp).toLocaleString()],
      ['mutated',   call.mutated ? 'yes' : 'no'],
      ['req frames', (call.request || []).length],
      ['res frames', (call.response || []).length],
    ];
    if (call.grpcMessage) rows.push(['message', call.grpcMessage]);
    if (call.error)       rows.push(['error', call.error]);

    content.innerHTML =
      '<div class="kv-wrap">' +
        '<table class="kv-table">' +
          rows.map(([k,v]) =>
            '<tr><td>' + escHtml(String(k)) + '</td><td>' + escHtml(String(v)) + '</td></tr>'
          ).join('') +
        '</table>' +
      '</div>';
  }
}

function renderFrames(frames, prefix) {
  if (frames.length === 1) {
    const j = frames[0].json || '(empty)';
    const id = prefix + '-f0';
    return (
      '<div class="code-wrap">' +
        '<div class="code-toolbar">' +
          '<span class="code-label">frame 0 · JSON</span>' +
          '<button class="copy-btn" id="' + id + '-btn" onclick="copyText(\'' + id + '\', \'' + id + '-btn\')">copy</button>' +
        '</div>' +
        '<pre class="code" id="' + id + '">' + colorJSON(j) + '</pre>' +
      '</div>'
    );
  }
  return '<div class="frames-list">' +
    frames.map((f, i) => {
      const j = f.json || '(empty)';
      const id = prefix + '-f' + i;
      return (
        '<div class="frame-item" id="fi-' + id + '">' +
          '<div class="frame-header" onclick="toggleFrame(\'' + id + '\')">' +
            '<span class="frame-idx">' + i + '</span>' +
            '<span style="font-family:var(--mono);font-size:11px;color:var(--text3)">JSON</span>' +
            '<button class="copy-btn" style="margin-left:auto;margin-right:8px" id="' + id + '-btn" onclick="event.stopPropagation();copyText(\'' + id + '\', \'' + id + '-btn\')">copy</button>' +
            '<span class="frame-chevron">▾</span>' +
          '</div>' +
          '<pre class="code" id="' + id + '">' + colorJSON(j) + '</pre>' +
        '</div>'
      );
    }).join('') +
  '</div>';
}

function toggleFrame(id) {
  const el = document.getElementById('fi-' + id);
  if (el) el.classList.toggle('collapsed');
}

// ── Replay ─────────────────────────────────────────────────
async function replayCall(id) {
  const btn = document.querySelector('.replay-btn');
  if (btn) { btn.textContent = 'Replaying…'; btn.disabled = true; }
  try {
    const r = await fetch('/api/replay/' + id, {method:'POST'});
    const d = await r.json();
    if (d.error) alert('Replay error: ' + d.error);
  } catch(e) { alert('Replay failed: ' + e); }
  finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<svg width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M2 9V2l7 3.5L2 9z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/></svg> Replay';
    }
  }
}

// ── Stats ──────────────────────────────────────────────────
function updateStats() {
  const okCount  = calls.filter(c => isOK(c)).length;
  const errCount = calls.length - okCount;
  document.getElementById('statTotal').innerHTML = calls.length + ' <span>calls</span>';
  document.getElementById('statOK').innerHTML    = okCount  + ' <span style="color:var(--text3)">ok</span>';
  document.getElementById('statErr').innerHTML   = errCount + ' <span style="color:var(--text3)">err</span>';
}

// ── Clear ──────────────────────────────────────────────────
function clearCalls() {
  calls = []; selectedID = null;
  renderList(); updateStats();
  document.getElementById('detail').innerHTML =
    '<div class="no-selection"><div class="arrow">←</div><div>Select a call</div></div>';
}

// ── Helpers ────────────────────────────────────────────────
function isOK(c) { return c.statusCode === '0' || c.statusCode === '' || !c.statusCode; }

function parseMethod(m) {
  // /package.Service/Method  or  package.Service/Method
  const clean = m.replace(/^\//, '');
  const slash = clean.lastIndexOf('/');
  if (slash === -1) return { pkg: '', svc: '', rpc: clean };
  const rpc = clean.slice(slash + 1);
  const svcFull = clean.slice(0, slash);
  const dot = svcFull.lastIndexOf('.');
  if (dot === -1) return { pkg: '', svc: svcFull, rpc };
  return { pkg: svcFull.slice(0, dot), svc: svcFull.slice(dot + 1), rpc };
}

function streamLabel(k) {
  return { unary:'unary', server_streaming:'server-stream', client_streaming:'client-stream', bidi_streaming:'bidi' }[k] || k;
}

function fmtDur(ms) {
  if (ms < 1)    return (ms * 1000).toFixed(0) + 'µs';
  if (ms < 1000) return ms.toFixed(1) + 'ms';
  return (ms / 1000).toFixed(2) + 's';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// JSON syntax highlighting
function colorJSON(raw) {
  try {
    const obj = JSON.parse(raw);
    return highlightJSON(obj, 0);
  } catch(_) {
    return escHtml(raw);
  }
}

function highlightJSON(val, depth) {
  const ind = '  '.repeat(depth);
  const ind1 = '  '.repeat(depth + 1);
  if (val === null)    return '<span class="json-null">null</span>';
  if (val === true)    return '<span class="json-bool">true</span>';
  if (val === false)   return '<span class="json-bool">false</span>';
  if (typeof val === 'number') return '<span class="json-num">' + val + '</span>';
  if (typeof val === 'string') return '<span class="json-str">' + escHtml(JSON.stringify(val)) + '</span>';
  if (Array.isArray(val)) {
    if (val.length === 0) return '<span class="json-punc">[]</span>';
    const items = val.map(v => ind1 + highlightJSON(v, depth + 1));
    return '<span class="json-punc">[</span>\n' + items.join('<span class="json-punc">,</span>\n') + '\n' + ind + '<span class="json-punc">]</span>';
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val);
    if (keys.length === 0) return '<span class="json-punc">{}</span>';
    const items = keys.map(k =>
      ind1 + '<span class="json-key">' + escHtml(JSON.stringify(k)) + '</span><span class="json-punc">: </span>' + highlightJSON(val[k], depth + 1)
    );
    return '<span class="json-punc">{</span>\n' + items.join('<span class="json-punc">,</span>\n') + '\n' + ind + '<span class="json-punc">}</span>';
  }
  return escHtml(String(val));
}

// grpcurl syntax highlighting
function colorGrpcurl(cmd) {
  return escHtml(cmd)
    .replace(/^(grpcurl)/,      '<span class="cmd-bin">$1</span>')
    .replace(/( -[\w-]+)/g,     '<span class="cmd-flag">$1</span>')
    .replace(/(&#39;[^&#]*&#39;|&quot;[^&]*&quot;)/g, '<span class="cmd-value">$1</span>');
}

// Copy helper
function copyText(elemId, btnId) {
  const el = document.getElementById(elemId);
  const btn = document.getElementById(btnId);
  if (!el || !btn) return;
  // Get plain text from potentially highlighted HTML
  const plain = el.innerText || el.textContent;
  navigator.clipboard.writeText(plain).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

init();
</script>
</body>
</html>`
}
