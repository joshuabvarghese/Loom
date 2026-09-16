package h2sniff

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Overflow here means "stop tapping this direction", not "apply
// backpressure" — real proxy traffic must never be slowed by a slow decoder.
const tapBufferedChunks = 4096

type Sniffer struct {
	Hub   *Hub
	Store *Store

	seq     atomic.Int64
	connSeq atomic.Int64
}

func New(historySize int) *Sniffer {
	return &Sniffer{Hub: NewHub(), Store: NewStore(historySize)}
}

func (s *Sniffer) nextSeq() int64 { return s.seq.Add(1) }

// Use for the client-facing leg, where Loom is the HTTP/2 server and the
// client sends the connection preface. The returned listener's connections
// behave identically to the originals; the tap only ever sees a duplicate
// of the bytes.
func (s *Sniffer) WrapListener(lis net.Listener) net.Listener {
	return &tapListener{Listener: lis, s: s}
}

type tapListener struct {
	net.Listener
	s *Sniffer
}

func (l *tapListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	connID := fmt.Sprintf("client-%d", l.s.connSeq.Add(1))
	return l.s.tap(conn, connID, true /* prefaceOnIn: we're the server */), nil
}

// Use from an http2.Transport's DialTLSContext/DialTLS hook, right after
// dialing, to tap a connection this process opened as an HTTP/2 client.
func (s *Sniffer) WrapDialedConn(conn net.Conn) net.Conn {
	connID := fmt.Sprintf("backend-%d", s.connSeq.Add(1))
	return s.tap(conn, connID, false /* prefaceOnIn: we're the client, preface goes out */)
}

func (s *Sniffer) tap(conn net.Conn, connID string, prefaceOnIn bool) net.Conn {
	inCh := make(chan []byte, tapBufferedChunks)
	outCh := make(chan []byte, tapBufferedChunks)
	tc := &tapConn{Conn: conn, inCh: inCh, outCh: outCh}

	go s.decodeLoop(connID, newChanReader(inCh), "in", prefaceOnIn)
	go s.decodeLoop(connID, newChanReader(outCh), "out", !prefaceOnIn)
	return tc
}

type tapConn struct {
	net.Conn
	inCh, outCh     chan []byte
	inDone, outDone atomic.Bool
}

func (t *tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.feed(t.inCh, &t.inDone, p[:n])
	}
	return n, err
}

func (t *tapConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.feed(t.outCh, &t.outDone, p[:n])
	}
	return n, err
}

// If the decoder falls behind, we stop tapping that direction for good
// rather than drop a chunk mid-stream: HTTP/2 framing has no resync
// markers, so a dropped chunk would desync every frame decoded after it.
func (t *tapConn) feed(ch chan []byte, done *atomic.Bool, p []byte) {
	if done.Load() {
		return
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case ch <- cp:
	default:
		if done.CompareAndSwap(false, true) {
			close(ch)
		}
	}
}

func (t *tapConn) Close() error {
	if t.inDone.CompareAndSwap(false, true) {
		close(t.inCh)
	}
	if t.outDone.CompareAndSwap(false, true) {
		close(t.outCh)
	}
	return t.Conn.Close()
}

type chanReader struct {
	ch  <-chan []byte
	buf []byte
}

func newChanReader(ch <-chan []byte) *chanReader { return &chanReader{ch: ch} }

func (r *chanReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		b, ok := <-r.ch
		if !ok {
			return 0, io.EOF
		}
		r.buf = b
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// decodeLoop never touches the real connection — r is already a private
// copy of the bytes fed by tapConn.
func (s *Sniffer) decodeLoop(connID string, r io.Reader, direction string, consumePreface bool) {
	if consumePreface {
		// The 24-byte preface isn't itself a frame; http2.Framer errors on
		// it if we don't skip it first.
		if _, err := io.CopyN(io.Discard, r, int64(len(http2.ClientPreface))); err != nil {
			return
		}
	}

	framer := http2.NewFramer(io.Discard, r) // io.Discard: this Framer only ever reads
	// Delegate HPACK decoding and HEADERS/CONTINUATION merging to the
	// Framer itself — it already handles padding and multi-frame header
	// blocks correctly.
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			return
		}

		fh := f.Header()
		ev := &FrameEvent{
			Seq:       s.nextSeq(),
			ConnID:    connID,
			StreamID:  fh.StreamID,
			Type:      fh.Type.String(),
			Length:    fh.Length,
			Direction: direction,
			Timestamp: time.Now(),
		}

		switch fr := f.(type) {
		case *http2.MetaHeadersFrame:
			ev.Flags = metaHeaderFlags(fr)
			ev.Path = fr.PseudoValue("path")
			ev.Method = fr.PseudoValue("method")
			ev.Status = fr.PseudoValue("status")
		case *http2.DataFrame:
			ev.Flags = flagNames(fh)
		case *http2.WindowUpdateFrame:
			ev.WindowIncrement = fr.Increment
		case *http2.RSTStreamFrame:
			ev.ErrorCode = fr.ErrCode.String()
		case *http2.GoAwayFrame:
			ev.ErrorCode = fr.ErrCode.String()
		case *http2.SettingsFrame:
			ev.Flags = flagNames(fh)
		case *http2.PingFrame:
			ev.Flags = flagNames(fh)
		}

		s.Hub.Publish(ev)
		s.Store.Add(ev)
	}
}

func metaHeaderFlags(mh *http2.MetaHeadersFrame) []string {
	var flags []string
	if mh.StreamEnded() {
		flags = append(flags, "END_STREAM")
	}
	if mh.HeadersEnded() {
		flags = append(flags, "END_HEADERS")
	}
	return flags
}

// flagNames covers flag bits meaningful outside HEADERS frames, which
// metaHeaderFlags handles instead.
func flagNames(fh http2.FrameHeader) []string {
	var flags []string
	switch fh.Type {
	case http2.FrameData:
		if fh.Flags.Has(http2.FlagDataEndStream) {
			flags = append(flags, "END_STREAM")
		}
		if fh.Flags.Has(http2.FlagDataPadded) {
			flags = append(flags, "PADDED")
		}
	case http2.FrameSettings:
		if fh.Flags.Has(http2.FlagSettingsAck) {
			flags = append(flags, "ACK")
		}
	case http2.FramePing:
		if fh.Flags.Has(http2.FlagPingAck) {
			flags = append(flags, "ACK")
		}
	}
	return flags
}
