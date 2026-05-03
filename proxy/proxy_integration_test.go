// Package proxy_test provides integration tests that run a real gRPC server,
// start the Loom proxy in front of it, and issue calls through a gRPC client.
//
// Run with:
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
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshuabvarghese/loom/internal/health"
	"github.com/joshuabvarghese/loom/internal/mutator"
	"github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	"github.com/joshuabvarghese/loom/proxy"

	// Generated stubs from testserver/gen/gen.go
	pb "github.com/joshuabvarghese/loom/testserver/gen"
)

// ── helpers ───────────────────────────────────────────────────────────────────

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

// startProxy wires up a Loom proxy pointing at backendAddr and returns the
// proxy's listen address plus a channel that receives every recorded call.
func startProxy(t *testing.T, backendAddr string, mut *mutator.Engine) (proxyAddr string, calls <-chan *recorder.CallRecord) {
	t.Helper()

	conn, err := grpc.NewClient(backendAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	rec, _ := recorder.New("")
	ch := rec.Hub.Subscribe()

	handler := proxy.NewHandler(proxy.Config{
		BackendAddr: backendAddr,
		GRPCConn:   conn,
		Reflector:  reflector.New(conn),
		Recorder:   rec,
		Mutator:    mut,
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
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewUserServiceClient(conn)
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestIntegration_UnaryCallPassthrough(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil)
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

	// Verify the proxy recorded the call.
	select {
	case call := <-calls:
		if call.Method != "/user.UserService/GetUser" {
			t.Errorf("recorded method=%q, want /user.UserService/GetUser", call.Method)
		}
		if call.StatusCode != "0" {
			t.Errorf("recorded status=%q, want 0 (OK)", call.StatusCode)
		}
		if call.DurationMs <= 0 {
			t.Error("recorded duration should be > 0")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for recorded call")
	}
}

func TestIntegration_RequestDecoding(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "hello"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	select {
	case call := <-calls:
		if len(call.Request) == 0 {
			t.Fatal("expected at least one request frame")
		}
		// The frame JSON should decode and contain the id field.
		var req map[string]any
		if jerr := json.Unmarshal([]byte(call.Request[0].JSON), &req); jerr != nil {
			t.Fatalf("request JSON invalid: %v — raw: %s", jerr, call.Request[0].JSON)
		}
		if req["id"] != "hello" {
			t.Errorf("decoded id=%v, want hello", req["id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for recorded call")
	}
}

func TestIntegration_MutationRuleApplied(t *testing.T) {
	// Build a mutation rule that rewrites id → "mutated"
	rulesJSON := `{"rules":[{"method":"/user.UserService/GetUser","direction":"request","field":"id","value":"mutated"}]}`

	mut, err := mutator.LoadRulesFromBytes([]byte(rulesJSON))
	if err != nil {
		t.Fatalf("build mutator: %v", err)
	}

	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, mut)
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "original"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	// The test server echoes the id back.
	if resp.GetId() != "mutated" {
		t.Errorf("backend saw id=%q, want mutated (mutation did not fire)", resp.GetId())
	}

	select {
	case call := <-calls:
		if !call.Mutated {
			t.Error("call.Mutated should be true when a rule fires")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for call")
	}
}

func TestIntegration_BackendDown(t *testing.T) {
	// Point proxy at a port nothing is listening on.
	proxyAddr, calls := startProxy(t, "127.0.0.1:1", nil) // port 1 is reserved, always refused
	client := grpcClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{Id: "x"})
	if err == nil {
		t.Fatal("expected error when backend is down, got nil")
	}

	select {
	case call := <-calls:
		if call.StatusCode == "0" {
			t.Error("status should be non-zero when backend is unreachable")
		}
		if call.Error == "" {
			t.Error("call.Error should be populated on backend failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for recorded error call")
	}
}

func TestIntegration_HealthEndpoint(t *testing.T) {
	// The proxy's health endpoint is served on the UI port, not the gRPC port.
	// This test starts a standalone health server to verify the HTTP shape.
	hc := health.New()
	hc.SetBackendReady(true)

	mux := http.NewServeMux()
	mux.Handle("/health", hc.Handler())
	mux.Handle("/live", hc.LiveHandler())
	mux.Handle("/ready", hc.ReadyHandler())

	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Close()

	base := "http://" + lis.Addr().String()

	for _, tc := range []struct {
		path       string
		wantStatus int
		wantField  string
		wantValue  string
	}{
		{"/live", 200, "status", "alive"},
		{"/ready", 200, "status", "ready"},
		{"/health", 200, "status", "ok"},
	} {
		resp, err := http.Get(base + tc.path)
		if err != nil {
			t.Errorf("%s: %v", tc.path, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("%s: HTTP %d, want %d", tc.path, resp.StatusCode, tc.wantStatus)
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Errorf("%s: decode body: %v", tc.path, err)
			continue
		}
		if body[tc.wantField] != tc.wantValue {
			t.Errorf("%s: %q=%v, want %q", tc.path, tc.wantField, body[tc.wantField], tc.wantValue)
		}
	}
}

// ── test server impl ──────────────────────────────────────────────────────────

type testUserServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *testUserServer) GetUser(_ context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	return &pb.User{Id: req.GetId(), Name: "Test User"}, nil
}

func (s *testUserServer) ListUsers(_ context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return &pb.ListUsersResponse{
		Users: []*pb.User{{Id: "1", Name: "Alice"}, {Id: "2", Name: "Bob"}},
	}, nil
}
