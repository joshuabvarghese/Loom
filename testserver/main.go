// testserver is a minimal gRPC backend with reflection enabled.
// Use it to test Loom locally.
//
// Terminal 1: go run ./testserver
// Terminal 2: go run . -backend localhost:50051
// Browser:    http://localhost:9998
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/joshuabvarghese/loom/testserver/gen"
)

// userServer implements pb.UserServiceServer.
type userServer struct {
	pb.UnimplementedUserServiceServer
}

// ── Unary ────────────────────────────────────────────────────────────────────

func (s *userServer) GetUser(req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	fmt.Printf("[backend] GetUser  user_id=%q\n", req.UserId)
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.UserId == "notfound" {
		return nil, status.Errorf(codes.NotFound, "user %q not found", req.UserId)
	}
	return &pb.GetUserResponse{
		User: &pb.User{
			Id:        req.UserId,
			Name:      "Ada Lovelace",
			Email:     "ada@example.com",
			Role:      pb.User_ROLE_ADMIN,
			CreatedAt: timestamppb.New(time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)),
		},
	}, nil
}

func (s *userServer) CreateUser(req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	fmt.Printf("[backend] CreateUser  name=%q email=%q\n", req.Name, req.Email)
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

// ── Server-streaming: ListUsers ──────────────────────────────────────────────

// sampleUsers is the fixed roster the test server streams.
var sampleUsers = []*pb.User{
	{Id: "u1", Name: "Ada Lovelace", Email: "ada@example.com", Role: pb.User_ROLE_ADMIN},
	{Id: "u2", Name: "Grace Hopper", Email: "grace@example.com", Role: pb.User_ROLE_EDITOR},
	{Id: "u3", Name: "Alan Turing", Email: "alan@example.com", Role: pb.User_ROLE_VIEWER},
	{Id: "u4", Name: "Dorothy Vaughan", Email: "dorothy@example.com", Role: pb.User_ROLE_EDITOR},
	{Id: "u5", Name: "Margaret Hamilton", Email: "margaret@example.com", Role: pb.User_ROLE_ADMIN},
}

func (s *userServer) ListUsers(req *pb.ListUsersRequest, stream pb.ListUsersServer) error {
	fmt.Printf("[backend] ListUsers  role_filter=%v limit=%d\n", req.RoleFilter, req.Limit)
	sent := 0
	for _, u := range sampleUsers {
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
		// Small delay so the streaming behaviour is visible in the UI.
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("[backend] ListUsers  sent %d user(s)\n", sent)
	return nil
}

// ── Client-streaming: BatchCreateUsers ───────────────────────────────────────

func (s *userServer) BatchCreateUsers(stream pb.BatchCreateUsersServer) (*pb.BatchCreateUsersResponse, error) {
	fmt.Printf("[backend] BatchCreateUsers  receiving...\n")
	var created []*pb.User
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if req.Name == "" || req.Email == "" {
			return nil, status.Error(codes.InvalidArgument, "name and email are required")
		}
		u := &pb.User{
			Id:        fmt.Sprintf("usr_%d", time.Now().UnixNano()),
			Name:      req.Name,
			Email:     req.Email,
			Role:      pb.User_ROLE_VIEWER,
			CreatedAt: timestamppb.Now(),
		}
		created = append(created, u)
		fmt.Printf("[backend] BatchCreateUsers  created %q\n", u.Name)
	}
	return &pb.BatchCreateUsersResponse{
		Created: int32(len(created)),
		Users:   created,
	}, nil
}

// ── Bidi-streaming: WatchUsers ────────────────────────────────────────────────

func (s *userServer) WatchUsers(stream pb.WatchUsersServer) error {
	fmt.Printf("[backend] WatchUsers  connected\n")
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		fmt.Printf("[backend] WatchUsers  watching user_id=%q\n", req.UserId)

		// Echo back a synthetic "created" event for the requested user.
		resp := &pb.WatchUsersResponse{
			Event: pb.WatchEvent_CREATED,
			User: &pb.User{
				Id:        req.UserId,
				Name:      "Watched User",
				Email:     fmt.Sprintf("%s@example.com", req.UserId),
				Role:      pb.User_ROLE_VIEWER,
				CreatedAt: timestamppb.Now(),
			},
		}
		if sendErr := stream.Send(resp); sendErr != nil {
			return sendErr
		}
	}
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	addr := flag.String("addr", ":50051", "listen address")
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterUserServiceServer(srv, &userServer{})
	reflection.Register(srv) // ← required for Loom to decode messages

	fmt.Printf("🚀 test backend on %s\n", *addr)
	fmt.Printf("   service: user.UserService\n")
	fmt.Printf("   methods: GetUser, CreateUser, ListUsers, BatchCreateUsers, WatchUsers\n\n")

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
