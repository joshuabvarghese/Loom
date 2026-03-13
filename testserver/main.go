// testserver is a minimal gRPC backend with reflection enabled.
// Use it to test Loom locally.
//
// Terminal 1: go run ./testserver
// Terminal 2: go run . -backend localhost:50051
// Browser:    http://localhost:9998
package main

import (
	"flag"
	"fmt"
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
// NOTE: method signatures must match the interface in gen/gen.go exactly.
// The gen package interface does NOT include context.Context (it's stripped
// in the dynamic handler shim — see gen.go _UserService_GetUser_Handler).
type userServer struct {
	pb.UnimplementedUserServiceServer
}

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
	fmt.Printf("   methods: GetUser, CreateUser\n\n")

	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
