package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshuabvarghese/loom/demo"
	"github.com/joshuabvarghese/loom/internal/metadata"
	"github.com/joshuabvarghese/loom/internal/mutator"
	"github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	"github.com/joshuabvarghese/loom/internal/store"
	"github.com/joshuabvarghese/loom/internal/webui"
	"github.com/joshuabvarghese/loom/proxy"
)

// Version is injected at build time via:
//
//	go build -ldflags "-X main.Version=v0.1.0" .
var Version = "dev"

const banner = `
  __
 |  |   ___   ___  ___
 |  |  / _ \ / _ \|  _|
 |  |_| (_) | (_) | |
 |____|\___/ \___/|_|

 gRPC L7 Debugging Proxy  %s
 ─────────────────────────────────────────
`

func main() {
	listenAddr := flag.String("listen", ":9999", "gRPC proxy listen address (point your client here)")
	backendAddr := flag.String("backend", "localhost:50051", "backend gRPC server address")
	verbose     := flag.Bool("verbose", false, "print extra debug info")
	noColor     := flag.Bool("no-color", false, "disable ANSI colour output")

	backendTLS     := flag.Bool("backend-tls", false, "connect to backend with TLS")
	backendTLSSkip := flag.Bool("backend-tls-skip-verify", false, "skip TLS certificate verification (insecure)")

	sessionName := flag.String("session", "default", "session name — history saved to ~/.loom/sessions/<name>.jsonl")
	logFile     := flag.String("log", "", "also write NDJSON to this file")
	mutateFile  := flag.String("mutate", "", "path to JSON mutation rules file")
	protoDir    := flag.String("proto-dir", "", "directory of .proto files (fallback when reflection is disabled)")
	uiAddr      := flag.String("ui", ":9998", "Web Inspector UI listen address (empty = disabled)")
	replayFile  := flag.String("replay", "", "replay an NDJSON log file then exit")
	demoMode    := flag.Bool("demo", false, "start with an embedded backend and send sample traffic — no setup needed")
	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("loom %s\n", Version)
		return
	}

	fmt.Printf(banner, Version)

	// ── Demo mode — embedded backend, zero config ─────────────────────────────
	if *demoMode {
		runDemoMode(*listenAddr, *uiAddr)
		return
	}

	// ── Replay mode ───────────────────────────────────────────────────────────
	if *replayFile != "" {
		runReplay(*replayFile, *backendAddr, *backendTLS)
		return
	}

	// ── Normal proxy mode ─────────────────────────────────────────────────────
	fmt.Printf("  Listening on : %s\n", *listenAddr)
	fmt.Printf("  Proxying to  : %s\n", *backendAddr)
	if *backendTLS {
		fmt.Printf("  TLS          : enabled (skip-verify=%v)\n", *backendTLSSkip)
	}
	fmt.Printf("  Session      : %s\n", *sessionName)
	if *logFile != "" {
		fmt.Printf("  Log file     : %s\n", *logFile)
	}
	if *mutateFile != "" {
		fmt.Printf("  Mutate rules : %s\n", *mutateFile)
	}
	if *protoDir != "" {
		fmt.Printf("  Proto dir    : %s\n", *protoDir)
	}
	if *uiAddr != "" {
		fmt.Printf("  Web UI       : http://localhost%s\n", *uiAddr)
	}
	fmt.Println()

	runProxy(proxyConfig{
		listenAddr:     *listenAddr,
		backendAddr:    *backendAddr,
		backendTLS:     *backendTLS,
		backendTLSSkip: *backendTLSSkip,
		sessionName:    *sessionName,
		logFile:        *logFile,
		mutateFile:     *mutateFile,
		protoDir:       *protoDir,
		uiAddr:         *uiAddr,
		verbose:        *verbose,
		noColor:        *noColor,
	})
}

// ── Demo ──────────────────────────────────────────────────────────────────────

func runDemoMode(listenAddr, uiAddr string) {
	fmt.Println("  ✨ Demo mode — no backend required")
	fmt.Println()

	backend, err := demo.Start("")
	if err != nil {
		log.Fatalf("❌  Demo backend: %v", err)
	}
	defer backend.Stop()

	fmt.Printf("  ✓ Embedded backend on %s\n", backend.Addr())
	if uiAddr != "" {
		fmt.Printf("  ✓ Web Inspector → http://localhost%s\n", uiAddr)
	}
	fmt.Println()

	runProxy(proxyConfig{
		listenAddr:  listenAddr,
		backendAddr: backend.Addr(),
		sessionName: "demo",
		uiAddr:      uiAddr,
		onReady: func(actualAddr string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			demo.SendSampleCalls(ctx, actualAddr)
		},
	})
}

// ── Core proxy runner ─────────────────────────────────────────────────────────

type proxyConfig struct {
	listenAddr     string
	backendAddr    string
	backendTLS     bool
	backendTLSSkip bool
	sessionName    string
	logFile        string
	mutateFile     string
	protoDir       string
	uiAddr         string
	verbose        bool
	noColor        bool
	// onReady is called in a goroutine once the proxy is listening.
	// It receives the actual bound address (e.g. "127.0.0.1:9999").
	onReady func(addr string)
}

func runProxy(cfg proxyConfig) {
	// ── Connect to backend ────────────────────────────────────────────────────
	var creds credentials.TransportCredentials
	if cfg.backendTLS {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: cfg.backendTLSSkip}) //nolint:gosec
	} else {
		creds = insecure.NewCredentials()
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()

	//nolint:staticcheck // grpc.DialContext is deprecated in v1.63 but still works in v1.61
	conn, err := grpc.DialContext(dialCtx, cfg.backendAddr,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		log.Fatalf("❌  Cannot connect to %s: %v\n\nIs the backend running?", cfg.backendAddr, err)
	}
	defer conn.Close()
	fmt.Printf("  ✓ Connected to backend at %s\n\n", cfg.backendAddr)

	// ── Reflector ─────────────────────────────────────────────────────────────
	res := reflector.New(conn)
	if cfg.protoDir != "" {
		if addErr := res.AddProtoDir(cfg.protoDir); addErr != nil {
			log.Printf("⚠  proto-dir: %v", addErr)
		} else {
			fmt.Printf("  ✓ Proto fallback registered from %s\n", cfg.protoDir)
		}
	}

	// ── Session store ─────────────────────────────────────────────────────────
	sessionStore, err := store.New(cfg.sessionName)
	if err != nil {
		log.Fatalf("❌  Session store: %v", err)
	}
	defer sessionStore.Close()

	si := sessionStore.SessionInfo()
	fmt.Printf("  ✓ Session %q  (%d historical calls)\n\n", si.Name, si.Count)
	rec := sessionStore.Recorder

	// Mirror to extra log file if requested
	if cfg.logFile != "" {
		extraRec, lerr := recorder.New(cfg.logFile)
		if lerr != nil {
			log.Fatalf("❌  Log file: %v", lerr)
		}
		defer extraRec.Close()
		ch := rec.Hub.Subscribe()
		go func() {
			for call := range ch {
				extraRec.Record(call)
			}
		}()
	}

	// ── Mutation engines ──────────────────────────────────────────────────────
	var mut *mutator.Engine
	var metaMut *metadata.Engine
	if cfg.mutateFile != "" {
		mut, err = mutator.LoadRules(cfg.mutateFile)
		if err != nil {
			log.Fatalf("❌  Mutation rules: %v", err)
		}
		fmt.Printf("  ✓ %d body mutation rule(s)\n", mut.RuleCount())

		metaMut, err = metadata.LoadRules(cfg.mutateFile)
		if err != nil {
			log.Fatalf("❌  Header rules: %v", err)
		}
		if metaMut.RuleCount() > 0 {
			fmt.Printf("  ✓ %d header mutation rule(s)\n", metaMut.RuleCount())
		}
	}

	// ── Web Inspector UI ──────────────────────────────────────────────────────
	if cfg.uiAddr != "" {
		proxyHostPort := "localhost" + cfg.listenAddr
		replayFn := func(call *recorder.CallRecord) (string, error) {
			return replaySingleCall(call, cfg.listenAddr, cfg.backendTLS)
		}
		uiServer := webui.NewWithOptions(rec, replayFn, proxyHostPort, cfg.backendTLS)
		uiLis, lisErr := net.Listen("tcp", cfg.uiAddr)
		if lisErr != nil {
			log.Fatalf("❌  UI listen %s: %v", cfg.uiAddr, lisErr)
		}
		go func() {
			if serveErr := http.Serve(uiLis, uiServer.Handler()); serveErr != nil && serveErr != http.ErrServerClosed {
				log.Printf("Web UI: %v", serveErr)
			}
		}()
		fmt.Printf("  ✓ Web Inspector at http://localhost%s\n\n", cfg.uiAddr)
	}

	// ── Proxy handler ─────────────────────────────────────────────────────────
	proxyCfg := proxy.Config{
		BackendAddr:          cfg.backendAddr,
		GRPCConn:             conn,
		Reflector:            res,
		Recorder:             rec,
		Mutator:              mut,
		Verbose:              cfg.verbose,
		Color:                !cfg.noColor,
		BackendTLS:           cfg.backendTLS,
		BackendTLSSkipVerify: cfg.backendTLSSkip,
	}
	// Guard against Go nil-interface-wrapping: a nil *metadata.Engine assigned
	// to an interface field produces a non-nil interface value.
	if metaMut != nil {
		proxyCfg.MetaMutator = metaMut
	}
	handler := proxy.NewHandler(proxyCfg)

	lis, lisErr := net.Listen("tcp", cfg.listenAddr)
	if lisErr != nil {
		log.Fatalf("❌  Proxy listen %s: %v", cfg.listenAddr, lisErr)
	}

	srv := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Println("\n  Shutting down…")
		srv.Close()
	}()

	fmt.Printf("  🧵 Loom is live — point your gRPC client at %s\n\n", cfg.listenAddr)
	fmt.Println("  ─────────────────────────────────────────")

	if cfg.onReady != nil {
		go cfg.onReady(lis.Addr().String())
	}

	if serveErr := srv.Serve(lis); serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatalf("Server: %v", serveErr)
	}
}

// ── Replay ────────────────────────────────────────────────────────────────────

func runReplay(ndjsonPath, backendAddr string, useTLS bool) {
	records, err := recorder.ReadNDJSON(ndjsonPath)
	if err != nil {
		log.Fatalf("❌  Cannot read replay file: %v", err)
	}
	fmt.Printf("  Replaying %d call(s) → %s\n\n", len(records), backendAddr)

	scheme := "http"
	var transport http.RoundTripper
	if useTLS {
		scheme = "https"
		transport = &http2.Transport{}
	} else {
		transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.DialTimeout(network, addr, 10*time.Second)
			},
		}
	}

	for i, call := range records {
		fmt.Printf("  [%d/%d] %s", i+1, len(records), call.Method)
		body := recorder.BuildRawBody(call.Request)
		url := fmt.Sprintf("%s://%s%s", scheme, backendAddr, call.Method)
		req, buildErr := http.NewRequest("POST", url, body)
		if buildErr != nil {
			fmt.Printf(" ✗ %v\n", buildErr)
			continue
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		resp, tripErr := transport.RoundTrip(req)
		if tripErr != nil {
			fmt.Printf(" ✗ %v\n", tripErr)
			continue
		}
		resp.Body.Close()
		code := resp.Trailer.Get("grpc-status")
		if code == "" {
			code = resp.Header.Get("grpc-status")
		}
		fmt.Printf(" → %s\n", grpcCodeName(code))
	}
}

func replaySingleCall(call *recorder.CallRecord, proxyAddr string, useTLS bool) (string, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	body := recorder.BuildRawBody(call.Request)
	url := fmt.Sprintf("%s://%s%s", scheme, proxyAddr, call.Method)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return fmt.Sprintf("replay-%d", time.Now().UnixNano()), nil
}

func grpcCodeName(code string) string {
	names := map[string]string{
		"0": "OK", "1": "CANCELLED", "2": "UNKNOWN",
		"5": "NOT_FOUND", "13": "INTERNAL", "14": "UNAVAILABLE",
	}
	if n, ok := names[code]; ok {
		return n + " (" + code + ")"
	}
	return "STATUS_" + code
}
