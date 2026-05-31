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
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshuabvarghese/loom/demo"
	"github.com/joshuabvarghese/loom/internal/circuitbreaker"
	"github.com/joshuabvarghese/loom/internal/config"
	"github.com/joshuabvarghese/loom/internal/health"
	"github.com/joshuabvarghese/loom/internal/metadata"
	"github.com/joshuabvarghese/loom/internal/metrics"
	"github.com/joshuabvarghese/loom/internal/mutator"
	"github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	slogpkg "github.com/joshuabvarghese/loom/internal/slog"
	"github.com/joshuabvarghese/loom/internal/store"
	"github.com/joshuabvarghese/loom/internal/webui"
	"github.com/joshuabvarghese/loom/proxy"
)

// Version is injected at build time via:
//
//	go build -ldflags "-X main.Version=v0.2.0" .
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
	verbose := flag.Bool("verbose", false, "print extra debug info")
	noColor := flag.Bool("no-color", false, "disable ANSI color output")
	backendTLS := flag.Bool("backend-tls", false, "connect to backend with TLS")
	backendTLSSkip := flag.Bool("backend-tls-skip-verify", false, "skip TLS certificate verification (insecure)")
	sessionName := flag.String("session", "default", "session name — history saved to ~/.loom/sessions/<name>.jsonl")
	logFile := flag.String("log", "", "also write NDJSON call log to this file")
	mutateFile := flag.String("mutate", "", "path to JSON mutation rules file")
	protoDir := flag.String("proto-dir", "", "directory of .proto files (fallback when server reflection is disabled)")
	uiAddr := flag.String("ui", ":9998", "Web Inspector + health/metrics listen address (empty = disabled)")
	replayFile := flag.String("replay", "", "replay an NDJSON log file then exit")
	demoMode := flag.Bool("demo", false, "start with an embedded backend and send sample traffic — no setup needed")
	showVersion := flag.Bool("version", false, "print version and exit")
	configFile := flag.String("config", "", "path to loom.toml or loom.yaml config file")
	flag.Parse()

	if *showVersion {
		fmt.Printf("loom %s\n", Version)
		return
	}

	fmt.Printf(banner, Version)

	// ── Load config file; CLI flags override file values ──────────────────────
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	applyConfigDefaults(cfg, listenAddr, backendAddr, sessionName, logFile, mutateFile, protoDir, uiAddr, verbose, noColor)

	// ── Structured logging ────────────────────────────────────────────────────
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		slogpkg.SetLevel(slogpkg.LevelDebug)
	case "warn":
		slogpkg.SetLevel(slogpkg.LevelWarn)
	case "error":
		slogpkg.SetLevel(slogpkg.LevelError)
	default:
		slogpkg.SetLevel(slogpkg.LevelInfo)
	}
	if *verbose {
		slogpkg.SetLevel(slogpkg.LevelDebug)
	}

	// ── Demo mode ─────────────────────────────────────────────────────────────
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
		fmt.Printf("  Health       : http://localhost%s/health\n", *uiAddr)
		fmt.Printf("  Metrics      : http://localhost%s/metrics\n", *uiAddr)
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

// applyConfigDefaults applies file config values to flag pointers only when
// the flag still holds its default value (i.e. was not explicitly passed).
func applyConfigDefaults(
	cfg *config.File,
	listenAddr, backendAddr, sessionName, logFile, mutateFile, protoDir, uiAddr *string,
	verbose, noColor *bool,
) {
	// Use flag.Visit to collect explicitly-set flag names.
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !set["listen"] && cfg.Listen != "" {
		*listenAddr = cfg.Listen
	}
	if !set["backend"] && cfg.Backend != "" {
		*backendAddr = cfg.Backend
	}
	if !set["session"] && cfg.Session != "" {
		*sessionName = cfg.Session
	}
	if !set["log"] && cfg.Log.File != "" {
		*logFile = cfg.Log.File
	}
	if !set["mutate"] && cfg.Mutate.File != "" {
		*mutateFile = cfg.Mutate.File
	}
	if !set["proto-dir"] && cfg.ProtoDir != "" {
		*protoDir = cfg.ProtoDir
	}
	if !set["ui"] && cfg.UI != "" {
		*uiAddr = cfg.UI
	}
	if !set["verbose"] && cfg.Verbose {
		*verbose = true
	}
	if !set["no-color"] && cfg.NoColor {
		*noColor = true
	}
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
	ctx := context.Background()

	// ── Circuit breaker ───────────────────────────────────────────────────────
	cb := circuitbreaker.New(circuitbreaker.Options{
		Threshold: 5,
		Timeout:   30 * time.Second,
	})

	// ── Health checker ────────────────────────────────────────────────────────
	hc := health.New()
	hc.SetCircuitBreaker(cb)

	// ── Connect to backend ────────────────────────────────────────────────────
	var creds credentials.TransportCredentials
	if cfg.backendTLS {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: cfg.backendTLSSkip}) //nolint:gosec
	} else {
		creds = insecure.NewCredentials()
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	//nolint:staticcheck // grpc.DialContext is deprecated in v1.63 but still works with v1.62
	conn, err := grpc.DialContext(dialCtx, cfg.backendAddr,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		log.Fatalf("❌  Cannot connect to %s: %v\n\nIs the backend running?", cfg.backendAddr, err)
	}
	defer conn.Close()

	hc.SetBackendReady(true)
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

	// Mirror to an extra log file if requested.
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

	// ── Web Inspector + health + metrics ──────────────────────────────────────
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

		uiMux := http.NewServeMux()
		uiMux.Handle("/", uiServer.Handler())
		uiMux.Handle("/health", hc.Handler())
		uiMux.Handle("/ready", hc.ReadyHandler())
		uiMux.Handle("/live", hc.LiveHandler())
		uiMux.Handle("/metrics", metrics.Handler())

		go func() {
			if serveErr := http.Serve(uiLis, uiMux); serveErr != nil && serveErr != http.ErrServerClosed {
				log.Printf("Web UI: %v", serveErr)
			}
		}()
		fmt.Printf("  ✓ Web Inspector at http://localhost%s\n\n", cfg.uiAddr)
	}

	// ── Proxy handler ─────────────────────────────────────────────────────────
	proxyCfg := proxy.Config{
		BackendAddr:          cfg.backendAddr,
		ListenAddr:           cfg.listenAddr,
		GRPCConn:             conn,
		Reflector:            res,
		Recorder:             rec,
		Mutator:              mut,
		CircuitBreaker:       cb,
		Verbose:              cfg.verbose,
		Color:                !cfg.noColor,
		BackendTLS:           cfg.backendTLS,
		BackendTLSSkipVerify: cfg.backendTLSSkip,
	}
	// Guard against nil-interface-wrapping: a nil *metadata.Engine assigned to
	// an interface field produces a non-nil interface value, which breaks nil checks.
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
		hc.SetBackendReady(false)
		fmt.Println("\n  Shutting down…")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutCancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	slogpkg.Info(ctx, "loom ready", "listen", cfg.listenAddr, "backend", cfg.backendAddr)
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
		"0": "OK", "1": "CANCELED", "2": "UNKNOWN",
		"5": "NOT_FOUND", "13": "INTERNAL", "14": "UNAVAILABLE",
	}
	if n, ok := names[code]; ok {
		return n + " (" + code + ")"
	}
	return "STATUS_" + code
}
