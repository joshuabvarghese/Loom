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
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/joshuabvarghese/loom/internal/circuitbreaker"
	"github.com/joshuabvarghese/loom/internal/health"
	"github.com/joshuabvarghese/loom/internal/mutator"
	"github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/reflector"
	"github.com/joshuabvarghese/loom/proxy"
	pb "github.com/joshuabvarghese/loom/testserver/gen"
)

// ── test helpers ──────────────────────────────────────────────────────────────

// startTestServer starts a gRPC server with our UserService and returns its address.
func startTestServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test server listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterUserServiceServer(srv, &testUserServer{})
	reflection.Register(srv) // needed for proxy to decode frames
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

// demoClient returns a DemoClient dialled at addr (uses dynamic proto).
func demoClient(t *testing.T, addr string) *pb.DemoClient {
	t.Helper()
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewDemoClient(conn)
}

func awaitCall(t *testing.T, ch <-chan *recorder.CallRecord) *recorder.CallRecord {
	t.Helper()
	select {
	case call := <-ch:
		return call
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for recorded call")
		return nil
	}
}

func awaitNCalls(t *testing.T, ch <-chan *recorder.CallRecord, n int) []*recorder.CallRecord {
	t.Helper()
	calls := make([]*recorder.CallRecord, 0, n)
	deadline := time.After(10 * time.Second)
	for len(calls) < n {
		select {
		case call := <-ch:
			calls = append(calls, call)
		case <-deadline:
			t.Fatalf("timed out waiting for %d calls; got %d", n, len(calls))
		}
	}
	return calls
}

// ── Unary tests ───────────────────────────────────────────────────────────────

func TestIntegration_UnaryCallPassthrough(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "42"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if resp.User == nil || resp.User.Id != "42" {
		t.Errorf("got user.id=%q, want 42", resp.User.Id)
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
	if call.StreamKind != recorder.StreamUnary {
		t.Errorf("StreamKind=%q, want unary", call.StreamKind)
	}
}

func TestIntegration_RequestDecoding(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "hello"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}

	call := awaitCall(t, calls)
	if len(call.Request) == 0 || call.Request[0].JSON == "" {
		t.Fatalf("expected decoded request JSON, got %+v", call.Request)
	}

	var req map[string]any
	if jerr := json.Unmarshal([]byte(call.Request[0].JSON), &req); jerr != nil {
		t.Fatalf("request JSON invalid: %v — raw: %s", jerr, call.Request[0].JSON)
	}
	if req["userId"] != "hello" {
		t.Errorf("decoded userId=%v, want hello", req["userId"])
	}
}

func TestIntegration_BackendDown_ReturnsUnavailable(t *testing.T) {
	// Port 1 is reserved and always refuses connections.
	proxyAddr, calls := startProxy(t, "127.0.0.1:1", nil, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "x"})
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
	cb := circuitbreaker.New(circuitbreaker.Options{Threshold: 1, Timeout: 60 * time.Second})

	proxyAddr, _ := startProxy(t, "127.0.0.1:1", nil, cb)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First call: hits the (down) backend and opens the circuit.
	_, _ = client.GetUser(ctx, &pb.GetUserRequest{UserId: "first"})

	time.Sleep(50 * time.Millisecond)

	if cb.State() != "open" {
		t.Errorf("circuit breaker should be open after first failure, got %q", cb.State())
	}

	// Second call: circuit is open — should fail immediately (no network dial).
	start := time.Now()
	_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "second"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error when circuit is open, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("circuit-open rejection took %v, want < 500ms", elapsed)
	}
}

// ── Server-streaming tests ────────────────────────────────────────────────────

func TestIntegration_ServerStreaming_ListUsers(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request all users (no role filter, no limit).
	responses, err := client.ListUsers(ctx, &pb.ListUsersRequest{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(responses) == 0 {
		t.Error("expected at least one user response")
	}
	for _, r := range responses {
		if r.User == nil {
			t.Error("each ListUsers response should have a user")
		}
	}

	call := awaitCall(t, calls)
	if call.Method != "/user.UserService/ListUsers" {
		t.Errorf("recorded method=%q, want /user.UserService/ListUsers", call.Method)
	}
	if call.StreamKind != recorder.StreamServer {
		t.Errorf("StreamKind=%q, want server_streaming", call.StreamKind)
	}
	if len(call.Response) == 0 {
		t.Error("expected response frames to be recorded")
	}
}

func TestIntegration_ServerStreaming_LimitRespected(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const limit = 2
	responses, err := client.ListUsers(ctx, &pb.ListUsersRequest{Limit: limit})
	if err != nil {
		t.Fatalf("ListUsers with limit: %v", err)
	}
	if len(responses) > limit {
		t.Errorf("got %d responses, want at most %d", len(responses), limit)
	}

	call := awaitCall(t, calls)
	if len(call.Response) > limit {
		t.Errorf("recorded %d response frames, want at most %d", len(call.Response), limit)
	}
}

// ── Client-streaming tests ────────────────────────────────────────────────────

func TestIntegration_ClientStreaming_BatchCreateUsers(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open a client-streaming RPC manually using a raw gRPC connection.
	conn, err := grpc.NewClient(proxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	streamDesc := &grpc.StreamDesc{ClientStreams: true}
	stream, err := conn.NewStream(ctx, streamDesc, "/user.UserService/BatchCreateUsers")
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}

	users := []struct{ Name, Email string }{
		{"Alice", "alice@example.com"},
		{"Bob", "bob@example.com"},
		{"Carol", "carol@example.com"},
	}
	for _, u := range users {
		dynReq := dynamicpb.NewMessage(pb.CreateUserReqDesc)
		f := pb.CreateUserReqDesc.Fields()
		dynReq.Set(f.ByName("name"), protoreflect.ValueOfString(u.Name))
		dynReq.Set(f.ByName("email"), protoreflect.ValueOfString(u.Email))
		if err := stream.SendMsg(dynReq); err != nil {
			t.Fatalf("SendMsg: %v", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	dynResp := dynamicpb.NewMessage(pb.BatchCreateRespDesc)
	if err := stream.RecvMsg(dynResp); err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}

	fields := pb.BatchCreateRespDesc.Fields()
	created := int32(dynResp.Get(fields.ByName("created")).Int())
	if created != int32(len(users)) {
		t.Errorf("BatchCreateUsers: created=%d, want %d", created, len(users))
	}

	call := awaitCall(t, calls)
	if call.Method != "/user.UserService/BatchCreateUsers" {
		t.Errorf("recorded method=%q", call.Method)
	}
	if call.StreamKind != recorder.StreamClient {
		t.Errorf("StreamKind=%q, want client_streaming", call.StreamKind)
	}
	if len(call.Request) != len(users) {
		t.Errorf("recorded %d request frames, want %d", len(call.Request), len(users))
	}
}

// ── Bidi-streaming tests ──────────────────────────────────────────────────────

func TestIntegration_BidiStreaming_WatchUsers(t *testing.T) {
	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(proxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	streamDesc := &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}
	stream, err := conn.NewStream(ctx, streamDesc, "/user.UserService/WatchUsers")
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}

	// Send two watch requests.
	watchIDs := []string{"u1", "u2"}
	for _, id := range watchIDs {
		dynReq := dynamicpb.NewMessage(pb.WatchUsersReqDesc)
		dynReq.Set(pb.WatchUsersReqDesc.Fields().ByName("user_id"), protoreflect.ValueOfString(id))
		if err := stream.SendMsg(dynReq); err != nil {
			t.Fatalf("SendMsg %q: %v", id, err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	// Receive one response per request.
	received := 0
	for {
		dynResp := dynamicpb.NewMessage(pb.WatchUsersRespDesc)
		if err := stream.RecvMsg(dynResp); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("RecvMsg: %v", err)
		}
		received++
	}

	if received != len(watchIDs) {
		t.Errorf("got %d WatchUsers responses, want %d", received, len(watchIDs))
	}

	call := awaitCall(t, calls)
	if call.Method != "/user.UserService/WatchUsers" {
		t.Errorf("recorded method=%q", call.Method)
	}
	if call.StreamKind != recorder.StreamBidi {
		t.Errorf("StreamKind=%q, want bidi_streaming", call.StreamKind)
	}
	if len(call.Request) != len(watchIDs) {
		t.Errorf("recorded %d req frames, want %d", len(call.Request), len(watchIDs))
	}
	if len(call.Response) != len(watchIDs) {
		t.Errorf("recorded %d resp frames, want %d", len(call.Response), len(watchIDs))
	}
}

// ── Health endpoint tests ─────────────────────────────────────────────────────

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
	httpClient := &http.Client{Timeout: 3 * time.Second}

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
			resp, err := httpClient.Get(base + tc.path)
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
	hc.SetBackendReady(false)

	mux := http.NewServeMux()
	mux.Handle("/ready", hc.ReadyHandler())
	mux.Handle("/health", hc.Handler())

	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })

	base := "http://" + lis.Addr().String()
	httpClient := &http.Client{Timeout: 3 * time.Second}

	for _, path := range []string{"/ready", "/health"} {
		resp, err := httpClient.Get(base + path)
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

// testUserServer implements all streaming and unary methods for the test suite.
type testUserServer struct {
	pb.UnimplementedUserServiceServer
}

func (s *testUserServer) GetUser(req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	return &pb.GetUserResponse{
		User: &pb.User{
			Id:    req.UserId,
			Name:  "Test User",
			Email: fmt.Sprintf("%s@test.com", req.UserId),
			Role:  pb.User_ROLE_VIEWER,
		},
	}, nil
}

func (s *testUserServer) CreateUser(req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	return &pb.CreateUserResponse{
		User: &pb.User{
			Id:        "new-id",
			Name:      req.Name,
			Email:     req.Email,
			Role:      pb.User_ROLE_VIEWER,
			CreatedAt: timestamppb.Now(),
		},
	}, nil
}

func (s *testUserServer) ListUsers(req *pb.ListUsersRequest, stream pb.ListUsersServer) error {
	users := []*pb.User{
		{Id: "1", Name: "Alice", Email: "alice@test.com", Role: pb.User_ROLE_ADMIN},
		{Id: "2", Name: "Bob", Email: "bob@test.com", Role: pb.User_ROLE_EDITOR},
		{Id: "3", Name: "Carol", Email: "carol@test.com", Role: pb.User_ROLE_VIEWER},
	}
	sent := 0
	for _, u := range users {
		if req.RoleFilter != pb.User_ROLE_UNSPECIFIED && u.Role != req.RoleFilter {
			continue
		}
		if err := stream.Send(&pb.GetUserResponse{User: u}); err != nil {
			return err
		}
		sent++
		if req.Limit > 0 && int32(sent) >= req.Limit {
			break
		}
	}
	return nil
}

func (s *testUserServer) BatchCreateUsers(stream pb.BatchCreateUsersServer) (*pb.BatchCreateUsersResponse, error) {
	var users []*pb.User
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		users = append(users, &pb.User{
			Id:    fmt.Sprintf("batch-%d", len(users)+1),
			Name:  req.Name,
			Email: req.Email,
			Role:  pb.User_ROLE_VIEWER,
		})
	}
	return &pb.BatchCreateUsersResponse{Created: int32(len(users)), Users: users}, nil
}

func (s *testUserServer) WatchUsers(stream pb.WatchUsersServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		resp := &pb.WatchUsersResponse{
			Event: pb.WatchEvent_CREATED,
			User: &pb.User{
				Id:    req.UserId,
				Name:  "Watched",
				Email: req.UserId + "@test.com",
				Role:  pb.User_ROLE_VIEWER,
			},
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func TestIntegration_MutationRuleApplied(t *testing.T) {
	// Mutation rule: set user_id → "mutated-id" on GetUser requests.
	// This proves the proxy decodes, mutates, and re-encodes request frames.
	rulesJSON := `[{"method":"/user.UserService/GetUser","direction":"request","set":{"userId":"mutated-id"}}]`
	mut, err := mutator.LoadRulesFromBytes([]byte(rulesJSON))
	if err != nil {
		t.Fatalf("build mutator: %v", err)
	}

	backendAddr := startTestServer(t)
	proxyAddr, calls := startProxy(t, backendAddr, mut, nil)
	client := demoClient(t, proxyAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "original"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	// The test server echoes the userId back — if the mutation fired, the
	// backend saw "mutated-id" and resp.User.Id should be "mutated-id".
	if resp.User == nil || resp.User.Id != "mutated-id" {
		t.Errorf("backend saw userId=%q, want mutated-id (mutation did not fire)", func() string {
			if resp.User != nil {
				return resp.User.Id
			}
			return "<nil>"
		}())
	}

	call := awaitCall(t, calls)
	if !call.Mutated {
		t.Error("call.Mutated should be true when a rule fires")
	}
}
