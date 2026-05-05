// Package proxy_test provides end-to-end integration tests for the Loom proxy.
//
// Each test starts a real gRPC server, starts a Loom proxy in front of it,
// and issues calls through a real gRPC client — nothing is mocked at the
// network or transport layer.
//
// Run all integration tests:
//
//	go test ./proxy/ -v -run TestIntegration
package proxy_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/joshuabvarghese/loom/internal/circuitbreaker"
	"github.com/joshuabvarghese/loom/internal/health"
	"github.com/joshuabvarghese/loom/internal/mutator"
	"github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	"github.com/joshuabvarghese/loom/proxy"
	pb "github.com/joshuabvarghese/loom/testserver/gen"
)

// ── test helpers ──────────────────────────────────────────────────────────────

// startTestServer starts a minimal gRPC server and returns its address.
func startTestServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test server listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterUserServiceServer(srv, &testUserServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	return lis.Addr().String()
}

// startProxy wires up a Loom proxy pointing at backendAddr.
// Returns the proxy's listen address and a channel of recorded calls.
func startProxy(t *testing.T, backendAddr string, mut *mutator.Engine, cb *circuitbreaker.Breaker) (string, <-chan *recorder.CallRecord) {
	t.Helper()

	conn, err := grpc.NewClient(backendAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	rec, _ := recorder.New("")
	ch := rec.Hub.Subscribe()
	t.Cleanup(func() { rec.Hub.Unsubscribe(ch) })

	handler := proxy.NewHandler(proxy.Config{
		BackendAddr:    backendAddr,
		GRPCConn:       conn,
		Reflector:      reflector.New(conn),
		Recorder:       rec,
		Mutator:        mut,
		CircuitBreaker: cb,
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	srv := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{})}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })

	return lis.Addr().String(), ch
}

// grpcClient returns a UserServiceClient dialled at addr.
func grpcClient(t *testing.T, addr string) pb.UserServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewUserServiceClient(conn)
}

func awaitCall(t *testing.T, ch <-chan *recorder.CallRecord) *recorder.CallRecord {
	t.Helper()
	select {
	case call := <-ch:
		return call
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for recorded call")
		return nil
	}
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestIntegration_UnaryCallPassthrough(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "42"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if resp.GetId() != "42" {
		t.Errorf("got id=%q, want 42", resp.GetId())
	}

	call := awaitCall(t, calls)
	if call.Method != "/user.UserService/GetUser" {
		t.Errorf("recorded method=%q, want /user.UserService/GetUser", call.Method)
	}
	if call.StatusCode != "0" {
		t.Errorf("recorded status=%q, want 0 (OK)", call.StatusCode)
	}
	if call.DurationMs <= 0 {
		t.Error("recorded duration should be > 0")
	}
}

func TestIntegration_RequestDecoding(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "hello"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	call := awaitCall(t, calls)
	if len(call.Request) == 0 {
		t.Fatal("expected at least one request frame")
	}
	var req map[string]any
	if jerr := json.Unmarshal([]byte(call.Request[0].JSON), &req); jerr != nil {
		t.Fatalf("request JSON invalid: %v — raw: %s", jerr, call.Request[0].JSON)
	}
	if req["id"] != "hello" {
		t.Errorf("decoded id=%v, want hello", req["id"])
	}
}

func TestIntegration_MutationRuleApplied(t *testing.T) {
	// Mutation rule: overwrite id → "mutated-id" on GetUser requests.
	rulesJSON := `[{"method":"/user.UserService/GetUser","direction":"request","set":{"id":"mutated-id"}}]`
	mut, err := mutator.LoadRulesFromBytes([]byte(rulesJSON))
	if err != nil {
		t.Fatalf("build mutator: %v", err)
	}

	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, mut, nil)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "original"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	// The test server echoes the ID back; the rule should have replaced it.
	if resp.GetId() != "mutated-id" {
		t.Errorf("backend saw id=%q, want mutated-id (mutation did not fire)", resp.GetId())
	}

	call := awaitCall(t, calls)
	if !call.Mutated {
		t.Error("call.Mutated should be true when a rule fires")
	}
}

func TestIntegration_BackendDown_ReturnsUnavailable(t *testing.T) {
	// Port 1 is reserved and always refuses connections.
	proxyAddr, calls := startProxy(t, "127.0.0.1:1", nil, nil)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "x"})
	if err == nil {
		t.Fatal("expected error when backend is down, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("got gRPC code %s, want UNAVAILABLE", st.Code())
	}

	call := awaitCall(t, calls)
	if call.StatusCode == "0" {
		t.Error("status should be non-zero when backend is unreachable")
	}
	if call.Error == "" {
		t.Error("call.Error should be populated on backend failure")
	}
}

func TestIntegration_CircuitBreaker_ShedsLoad(t *testing.T) {
	// A circuit breaker with threshold=1 opens after a single failure.
	cb := circuitbreaker.New(circuitbreaker.Options{Threshold: 1, Timeout: 60 * time.Second})

	// Port 1 is always refused — the circuit opens after the first call.
	proxyAddr, _ := startProxy(t, "127.0.0.1:1", nil, cb)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First call: hits the backend (which is down) and opens the circuit.
	_, _ = client.GetUser(ctx, &pb.GetUserRequest{Id: "first"})

	// Give the proxy a moment to update the circuit state.
	time.Sleep(50 * time.Millisecond)

	if cb.State() != "open" {
		t.Errorf("circuit breaker should be open after first failure, got %q", cb.State())
	}

	// Second call: circuit is open — should fail immediately.
	start := time.Now()
	_, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "second"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error when circuit is open, got nil")
	}
	// A circuit-open rejection should be very fast (< 500ms — no network dial).
	if elapsed > 500*time.Millisecond {
		t.Errorf("circuit-open rejection took %v, want < 500ms", elapsed)
	}
}

func TestIntegration_HealthEndpoints(t *testing.T) {
	hc := health.New()
	hc.SetBackendReady(true)

	mux := http.NewServeMux()
	mux.Handle("/health", hc.Handler())
	mux.Handle("/live", hc.LiveHandler())
	mux.Handle("/ready", hc.ReadyHandler())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })

	base := "http://" + lis.Addr().String()
	client := &http.Client{Timeout: 3 * time.Second}

	tests := []struct {
		path       string
		wantStatus int
		wantField  string
		wantValue  string
	}{
		{"/live", 200, "status", "alive"},
		{"/ready", 200, "status", "ready"},
		{"/health", 200, "status", "ok"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := client.Get(base + tc.path)
			if err != nil {
				t.Fatalf("%s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("%s: HTTP %d, want %d", tc.path, resp.StatusCode, tc.wantStatus)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("%s: decode: %v", tc.path, err)
			}
			if body[tc.wantField] != tc.wantValue {
				t.Errorf("%s: %q=%v, want %q", tc.path, tc.wantField, body[tc.wantField], tc.wantValue)
			}
		})
	}
}

func TestIntegration_HealthDegraded_WhenBackendDown(t *testing.T) {
	hc := health.New()
	hc.SetBackendReady(false) // simulate disconnected backend

	mux := http.NewServeMux()
	mux.Handle("/ready", hc.ReadyHandler())
	mux.Handle("/health", hc.Handler())

	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })

	base := "http://" + lis.Addr().String()
	client := &http.Client{Timeout: 3 * time.Second}

	for _, path := range []string{"/ready", "/health"} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s: want 503, got %d", path, resp.StatusCode)
		}
	}
}

// ── embedded test gRPC server ─────────────────────────────────────────────────

type testUserServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *testUserServer) GetUser(_ context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	return &pb.User{Id: req.GetId(), Name: "Test User"}, nil
}

func (s *testUserServer) ListUsers(_ context.Context, _ *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return &pb.ListUsersResponse{
		Users: []*pb.User{
			{Id: "1", Name: "Alice"},
			{Id: "2", Name: "Bob"},
		},
	}, nil
}
