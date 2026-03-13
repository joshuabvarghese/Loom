// Package demo provides a self-contained demonstration mode for Loom.
//
// It embeds a fake gRPC backend so users can explore the Web Inspector
// immediately — no external server required.
//
// Usage:
//
//	loom -demo
//	# then open http://localhost:9998
package demo

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/joshuabvarghese/loom/testserver/gen"
)

// BackendServer is a live in-process gRPC backend for demo mode.
type BackendServer struct {
	addr   string
	server *grpc.Server
}

// Start starts an embedded gRPC backend. addr may be empty (picks a free port)
// or a specific address like "localhost:50052".
// Returns the actual listen address.
func Start(addr string) (*BackendServer, error) {
	if addr == "" {
		addr = "localhost:0"
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("demo backend listen: %w", err)
	}

	srv := grpc.NewServer()
	pb.RegisterUserServiceServer(srv, &demoServer{})
	reflection.Register(srv)

	bs := &BackendServer{addr: lis.Addr().String(), server: srv}
	go func() {
		if serveErr := srv.Serve(lis); serveErr != nil {
			log.Printf("demo backend: %v", serveErr)
		}
	}()

	// Give the server a moment to be ready
	time.Sleep(80 * time.Millisecond)
	return bs, nil
}

// Addr returns the network address the backend is listening on.
func (b *BackendServer) Addr() string { return b.addr }

// Stop gracefully stops the embedded backend.
func (b *BackendServer) Stop() { b.server.GracefulStop() }

// SendSampleCalls sends representative gRPC calls through proxyAddr to populate
// the Web Inspector with realistic traffic. Errors on "expected" calls (e.g.
// NOT_FOUND) are silenced — they're intentional to demonstrate error display.
func SendSampleCalls(ctx context.Context, proxyAddr string) {
	// Brief pause so the proxy is fully ready
	time.Sleep(300 * time.Millisecond)

	//nolint:staticcheck // grpc.Dial still works in v1.61; upgrade to grpc.NewClient when bumping to v1.63+
	conn, err := grpc.Dial(proxyAddr, //nolint:staticcheck
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Printf("demo: connecting to proxy %s: %v", proxyAddr, err)
		return
	}
	defer conn.Close()

	client := pb.NewDemoClient(conn)

	samples := []struct {
		label  string
		callFn func() error
	}{
		{"GetUser alice-123 (OK)", func() error {
			_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "alice-123"})
			return err
		}},
		{"GetUser bob-456 (OK)", func() error {
			_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "bob-456"})
			return err
		}},
		{"CreateUser grace@example.com", func() error {
			_, err := client.CreateUser(ctx, &pb.CreateUserRequest{
				Name: "Grace Hopper", Email: "grace@example.com",
			})
			return err
		}},
		{"GetUser notfound (NOT_FOUND)", func() error {
			_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "notfound"})
			return err
		}},
		{"GetUser empty (INVALID_ARGUMENT)", func() error {
			_, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: ""})
			return err
		}},
		{"CreateUser alan@example.com", func() error {
			_, err := client.CreateUser(ctx, &pb.CreateUserRequest{
				Name: "Alan Turing", Email: "alan@example.com",
			})
			return err
		}},
	}

	fmt.Println("  Sending sample calls through the proxy…")
	for _, s := range samples {
		callErr := s.callFn()
		if callErr != nil && !isExpectedDemoError(callErr) {
			fmt.Printf("  ⚠ [%s]: %v\n", s.label, callErr)
		} else {
			fmt.Printf("  ✓ %s\n", s.label)
		}
		time.Sleep(120 * time.Millisecond)
	}
	fmt.Println()
	fmt.Println("  🎉 Demo traffic sent — refresh the Web Inspector to see all calls!")
	fmt.Println()
}

func isExpectedDemoError(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.NotFound, codes.InvalidArgument:
		return true
	}
	return false
}

// ── Embedded demo gRPC server ─────────────────────────────────────────────────

type demoServer struct {
	pb.UnimplementedUserServiceServer
}

var seedUsers = map[string]*pb.User{
	"alice-123": {
		Id: "alice-123", Name: "Ada Lovelace", Email: "ada@example.com",
		Role:      pb.User_ROLE_ADMIN,
		CreatedAt: timestamppb.New(time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)),
	},
	"bob-456": {
		Id: "bob-456", Name: "Alan Turing", Email: "alan@example.com",
		Role:      pb.User_ROLE_EDITOR,
		CreatedAt: timestamppb.New(time.Date(2024, 3, 22, 14, 30, 0, 0, time.UTC)),
	},
}

func (s *demoServer) GetUser(req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.UserId == "notfound" {
		return nil, status.Errorf(codes.NotFound, "user %q does not exist", req.UserId)
	}
	if u, ok := seedUsers[req.UserId]; ok {
		return &pb.GetUserResponse{User: u}, nil
	}
	// Generate a plausible user for any other ID
	return &pb.GetUserResponse{
		User: &pb.User{
			Id:        req.UserId,
			Name:      "Demo User " + strings.ToUpper(req.UserId[:1]),
			Email:     req.UserId + "@demo.example",
			Role:      pb.User_ROLE_VIEWER,
			CreatedAt: timestamppb.Now(),
		},
	}, nil
}

func (s *demoServer) CreateUser(req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	if req.Name == "" || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "name and email are required")
	}
	return &pb.CreateUserResponse{
		User: &pb.User{
			Id:        fmt.Sprintf("usr_%d", time.Now().UnixMilli()),
			Name:      req.Name,
			Email:     req.Email,
			Role:      pb.User_ROLE_VIEWER,
			CreatedAt: timestamppb.Now(),
		},
	}, nil
}
