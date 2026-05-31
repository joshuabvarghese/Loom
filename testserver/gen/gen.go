// Package gen provides a self-bootstrapping protobuf descriptor registry for
// the Loom test server. It constructs the FileDescriptor for user.proto
// programmatically at init-time so no protoc code generation is required.
//
// Once you have protoc and protoc-gen-go installed, you can replace this file
// with the normal generated output by running:
//
//	protoc --go_out=. --go_opt=paths=source_relative \
//	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
//	       testserver/user.proto
package gen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ──────────────────────────────────────────────────────────────
// Global descriptor references (populated in init)
// ──────────────────────────────────────────────────────────────

var (
	once sync.Once

	FileDesc protoreflect.FileDescriptor

	UserDesc            protoreflect.MessageDescriptor
	GetUserReqDesc      protoreflect.MessageDescriptor
	GetUserRespDesc     protoreflect.MessageDescriptor
	CreateUserReqDesc   protoreflect.MessageDescriptor
	CreateUserRespDesc  protoreflect.MessageDescriptor
	ListUsersReqDesc    protoreflect.MessageDescriptor
	BatchCreateRespDesc protoreflect.MessageDescriptor
	WatchUsersReqDesc   protoreflect.MessageDescriptor
	WatchUsersRespDesc  protoreflect.MessageDescriptor
	WatchUsersEventDesc protoreflect.EnumDescriptor

	UserRoleDesc protoreflect.EnumDescriptor
)

func init() {
	once.Do(buildDescriptors)
}

func ptr[T any](v T) *T { return &v }

// buildDescriptors constructs the FileDescriptorProto for user.proto in Go
// and registers it with the global proto registry. This is equivalent to
// what protoc-gen-go embeds as raw bytes in generated code.
func buildDescriptors() {
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()

	fdp := &descriptorpb.FileDescriptorProto{
		Name:       ptr("user.proto"),
		Package:    ptr("user"),
		Dependency: []string{"google/protobuf/timestamp.proto"},
		Options:    &descriptorpb.FileOptions{GoPackage: ptr("github.com/joshuabvarghese/loom/testserver/gen")},
		Syntax:     ptr("proto3"),

		EnumType: []*descriptorpb.EnumDescriptorProto{
			{
				Name: ptr("WatchUsersEvent"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: ptr("EVENT_UNSPECIFIED"), Number: ptr(int32(0))},
					{Name: ptr("EVENT_CREATED"), Number: ptr(int32(1))},
					{Name: ptr("EVENT_UPDATED"), Number: ptr(int32(2))},
					{Name: ptr("EVENT_DELETED"), Number: ptr(int32(3))},
				},
			},
		},

		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: ptr("User"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("id", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "id"),
					field("name", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "name"),
					field("email", 3, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "email"),
					fieldEnum("role", 4, ".user.User.Role", "role"),
					fieldMsg("created_at", 5, ".google.protobuf.Timestamp", "createdAt"),
				},
				EnumType: []*descriptorpb.EnumDescriptorProto{
					{
						Name: ptr("Role"),
						Value: []*descriptorpb.EnumValueDescriptorProto{
							{Name: ptr("ROLE_UNSPECIFIED"), Number: ptr(int32(0))},
							{Name: ptr("ROLE_ADMIN"), Number: ptr(int32(1))},
							{Name: ptr("ROLE_EDITOR"), Number: ptr(int32(2))},
							{Name: ptr("ROLE_VIEWER"), Number: ptr(int32(3))},
						},
					},
				},
			},
			{
				Name: ptr("GetUserRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("user_id", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "userId"),
				},
			},
			{
				Name: ptr("GetUserResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					fieldMsg("user", 1, ".user.User", "user"),
				},
			},
			{
				Name: ptr("CreateUserRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("name", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "name"),
					field("email", 2, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "email"),
				},
			},
			{
				Name: ptr("CreateUserResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					fieldMsg("user", 1, ".user.User", "user"),
				},
			},
			// ListUsersRequest — server-streaming input
			{
				Name: ptr("ListUsersRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					fieldEnum("role_filter", 1, ".user.User.Role", "roleFilter"),
					field("limit", 2, descriptorpb.FieldDescriptorProto_TYPE_INT32, "", "limit"),
				},
			},
			// BatchCreateUsersResponse — client-streaming output
			{
				Name: ptr("BatchCreateUsersResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("created", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32, "", "created"),
					{
						Name:     ptr("users"),
						Number:   ptr(int32(2)),
						Label:    repeated,
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: ptr(".user.User"),
						JsonName: ptr("users"),
					},
				},
			},
			// WatchUsersRequest — bidi-streaming input
			{
				Name: ptr("WatchUsersRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					field("user_id", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, "", "userId"),
				},
			},
			// WatchUsersResponse — bidi-streaming output
			{
				Name: ptr("WatchUsersResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					fieldEnum("event", 1, ".user.WatchUsersEvent", "event"),
					fieldMsg("user", 2, ".user.User", "user"),
				},
			},
		},

		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: ptr("UserService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       ptr("GetUser"),
						InputType:  ptr(".user.GetUserRequest"),
						OutputType: ptr(".user.GetUserResponse"),
					},
					{
						Name:       ptr("CreateUser"),
						InputType:  ptr(".user.CreateUserRequest"),
						OutputType: ptr(".user.CreateUserResponse"),
					},
					{
						Name:            ptr("ListUsers"),
						InputType:       ptr(".user.ListUsersRequest"),
						OutputType:      ptr(".user.GetUserResponse"),
						ServerStreaming: ptr(true),
					},
					{
						Name:            ptr("BatchCreateUsers"),
						InputType:       ptr(".user.CreateUserRequest"),
						OutputType:      ptr(".user.BatchCreateUsersResponse"),
						ClientStreaming: ptr(true),
					},
					{
						Name:            ptr("WatchUsers"),
						InputType:       ptr(".user.WatchUsersRequest"),
						OutputType:      ptr(".user.WatchUsersResponse"),
						ClientStreaming: ptr(true),
						ServerStreaming: ptr(true),
					},
				},
			},
		},
	}

	// Resolve dependencies first — timestamp.proto must already be registered
	// by the timestamppb package (imported below via side-effect).
	_ = timestamppb.Timestamp{} // ensure timestamppb registers its descriptor

	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		panic(fmt.Sprintf("github.com/joshuabvarghese/loom/testserver/gen: building file descriptor: %v", err))
	}

	if err := protoregistry.GlobalFiles.RegisterFile(fd); err != nil {
		// Already registered (e.g. in tests that import this package twice)
		if existingFD, lookupErr := protoregistry.GlobalFiles.FindFileByPath("user.proto"); lookupErr == nil {
			fd = existingFD
		} else {
			panic(fmt.Sprintf("github.com/joshuabvarghese/loom/testserver/gen: registering file descriptor: %v", err))
		}
	}

	FileDesc = fd
	msgs := fd.Messages()
	UserDesc = msgs.ByName("User")
	GetUserReqDesc = msgs.ByName("GetUserRequest")
	GetUserRespDesc = msgs.ByName("GetUserResponse")
	CreateUserReqDesc = msgs.ByName("CreateUserRequest")
	CreateUserRespDesc = msgs.ByName("CreateUserResponse")
	ListUsersReqDesc = msgs.ByName("ListUsersRequest")
	BatchCreateRespDesc = msgs.ByName("BatchCreateUsersResponse")
	WatchUsersReqDesc = msgs.ByName("WatchUsersRequest")
	WatchUsersRespDesc = msgs.ByName("WatchUsersResponse")
	WatchUsersEventDesc = fd.Enums().ByName("WatchUsersEvent")
	UserRoleDesc = UserDesc.Enums().ByName("Role")

	// Register all message types so proto.Marshal / Unmarshal can find them
	for _, name := range []protoreflect.Name{
		"User", "GetUserRequest", "GetUserResponse",
		"CreateUserRequest", "CreateUserResponse",
		"ListUsersRequest", "BatchCreateUsersResponse",
		"WatchUsersRequest", "WatchUsersResponse",
	} {
		registerType(fd.Messages().ByName(name))
	}
}

func registerType(md protoreflect.MessageDescriptor) {
	mt := dynamicpb.NewMessageType(md)
	_ = protoregistry.GlobalTypes.RegisterMessage(mt) // ignore "already registered"
}

// ── protobuf field builder helpers ────────────────────────────────────────────

func field(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName, json string) *descriptorpb.FieldDescriptorProto {
	f := &descriptorpb.FieldDescriptorProto{
		Name:     ptr(name),
		Number:   ptr(num),
		Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
		Type:     typ.Enum(),
		JsonName: ptr(json),
	}
	if typeName != "" {
		f.TypeName = ptr(typeName)
	}
	return f
}

func fieldMsg(name string, num int32, typeName, json string) *descriptorpb.FieldDescriptorProto {
	return field(name, num, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName, json)
}

func fieldEnum(name string, num int32, typeName, json string) *descriptorpb.FieldDescriptorProto {
	return field(name, num, descriptorpb.FieldDescriptorProto_TYPE_ENUM, typeName, json)
}

// ──────────────────────────────────────────────────────────────
// Go types mirroring the proto messages
// ──────────────────────────────────────────────────────────────

// UserRole mirrors the User.Role enum.
type UserRole int32

const (
	User_ROLE_UNSPECIFIED UserRole = 0
	User_ROLE_ADMIN       UserRole = 1
	User_ROLE_EDITOR      UserRole = 2
	User_ROLE_VIEWER      UserRole = 3
)

// WatchEvent mirrors WatchUsersEvent.
type WatchEvent int32

const (
	WatchEvent_UNSPECIFIED WatchEvent = 0
	WatchEvent_CREATED     WatchEvent = 1
	WatchEvent_UPDATED     WatchEvent = 2
	WatchEvent_DELETED     WatchEvent = 3
)

// User is a dynamic wrapper so test server code can use field helpers.
type User struct {
	Id        string
	Name      string
	Email     string
	Role      UserRole
	CreatedAt *timestamppb.Timestamp
}

// GetUserRequest is the decoded request for GetUser.
type GetUserRequest struct{ UserId string }

// GetUserResponse wraps the response User.
type GetUserResponse struct{ User *User }

// CreateUserRequest holds new user fields.
type CreateUserRequest struct{ Name, Email string }

// CreateUserResponse wraps the created User.
type CreateUserResponse struct{ User *User }

// ListUsersRequest is the request for ListUsers (server-streaming).
type ListUsersRequest struct {
	RoleFilter UserRole
	Limit      int32
}

// BatchCreateUsersResponse summarizes a client-streaming batch create.
type BatchCreateUsersResponse struct {
	Created int32
	Users   []*User
}

// WatchUsersRequest is sent by the client to subscribe to events.
type WatchUsersRequest struct{ UserId string }

// WatchUsersResponse is sent by the server for each user event.
type WatchUsersResponse struct {
	Event WatchEvent
	User  *User
}

// ──────────────────────────────────────────────────────────────
// gRPC server interface & registration
// ──────────────────────────────────────────────────────────────

// ListUsersServer is the server-side streaming interface for ListUsers.
type ListUsersServer interface {
	Send(*GetUserResponse) error
	grpc.ServerStream
}

// BatchCreateUsersServer is the server-side interface for BatchCreateUsers.
type BatchCreateUsersServer interface {
	Recv() (*CreateUserRequest, error)
	SendAndClose(*BatchCreateUsersResponse) error
	grpc.ServerStream
}

// WatchUsersServer is the server-side bidi interface for WatchUsers.
type WatchUsersServer interface {
	Send(*WatchUsersResponse) error
	Recv() (*WatchUsersRequest, error)
	grpc.ServerStream
}

// UserServiceServer is the server-side interface for UserService.
type UserServiceServer interface {
	GetUser(*GetUserRequest) (*GetUserResponse, error)
	CreateUser(*CreateUserRequest) (*CreateUserResponse, error)
	ListUsers(*ListUsersRequest, ListUsersServer) error
	BatchCreateUsers(BatchCreateUsersServer) (*BatchCreateUsersResponse, error)
	WatchUsers(WatchUsersServer) error
}

// UnimplementedUserServiceServer provides default (unimplemented) handlers.
type UnimplementedUserServiceServer struct{}

func (UnimplementedUserServiceServer) GetUser(*GetUserRequest) (*GetUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetUser not implemented")
}
func (UnimplementedUserServiceServer) CreateUser(*CreateUserRequest) (*CreateUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateUser not implemented")
}
func (UnimplementedUserServiceServer) ListUsers(_ *ListUsersRequest, _ ListUsersServer) error {
	return status.Error(codes.Unimplemented, "ListUsers not implemented")
}
func (UnimplementedUserServiceServer) BatchCreateUsers(_ BatchCreateUsersServer) (*BatchCreateUsersResponse, error) {
	return nil, status.Error(codes.Unimplemented, "BatchCreateUsers not implemented")
}
func (UnimplementedUserServiceServer) WatchUsers(_ WatchUsersServer) error {
	return status.Error(codes.Unimplemented, "WatchUsers not implemented")
}

// RegisterUserServiceServer registers srv with the gRPC server s.
func RegisterUserServiceServer(s *grpc.Server, srv UserServiceServer) {
	s.RegisterService(&UserService_ServiceDesc, srv)
}

// UserService_ServiceDesc is the grpc.ServiceDesc for UserService.
var UserService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "user.UserService",
	HandlerType: (*UserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetUser", Handler: _UserService_GetUser_Handler},
		{MethodName: "CreateUser", Handler: _UserService_CreateUser_Handler},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ListUsers",
			Handler:       _UserService_ListUsers_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "BatchCreateUsers",
			Handler:       _UserService_BatchCreateUsers_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "WatchUsers",
			Handler:       _UserService_WatchUsers_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "user.proto",
}

// ──────────────────────────────────────────────────────────────
// Unary method handlers
// ──────────────────────────────────────────────────────────────

func _UserService_GetUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	dynReq := dynamicpb.NewMessage(GetUserReqDesc)
	if err := dec(dynReq); err != nil {
		return nil, err
	}
	req := &GetUserRequest{
		UserId: dynReq.Get(GetUserReqDesc.Fields().ByName("user_id")).String(),
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/user.UserService/GetUser"}
	var resp *GetUserResponse
	var err error
	if interceptor == nil {
		resp, err = srv.(UserServiceServer).GetUser(req)
	} else {
		result, iErr := interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.(UserServiceServer).GetUser(req.(*GetUserRequest))
		})
		if iErr != nil {
			return nil, iErr
		}
		resp = result.(*GetUserResponse)
	}
	if err != nil {
		return nil, err
	}
	return marshalGetUserResponse(resp)
}

func _UserService_CreateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	dynReq := dynamicpb.NewMessage(CreateUserReqDesc)
	if err := dec(dynReq); err != nil {
		return nil, err
	}
	fields := CreateUserReqDesc.Fields()
	req := &CreateUserRequest{
		Name:  dynReq.Get(fields.ByName("name")).String(),
		Email: dynReq.Get(fields.ByName("email")).String(),
	}
	var resp *CreateUserResponse
	var err error
	if interceptor == nil {
		resp, err = srv.(UserServiceServer).CreateUser(req)
	} else {
		result, iErr := interceptor(ctx, req, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/user.UserService/CreateUser"}, func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.(UserServiceServer).CreateUser(req.(*CreateUserRequest))
		})
		if iErr != nil {
			return nil, iErr
		}
		resp = result.(*CreateUserResponse)
	}
	if err != nil {
		return nil, err
	}
	return marshalCreateUserResponse(resp)
}

// ──────────────────────────────────────────────────────────────
// Streaming method handlers
// ──────────────────────────────────────────────────────────────

// ── ListUsers (server-streaming) ──────────────────────────────

type listUsersServer struct{ grpc.ServerStream }

func (s *listUsersServer) Send(resp *GetUserResponse) error {
	msg, err := marshalGetUserResponse(resp)
	if err != nil {
		return err
	}
	return s.ServerStream.SendMsg(msg)
}

func _UserService_ListUsers_Handler(srv interface{}, stream grpc.ServerStream) error {
	dynReq := dynamicpb.NewMessage(ListUsersReqDesc)
	if err := stream.RecvMsg(dynReq); err != nil {
		return err
	}
	fields := ListUsersReqDesc.Fields()
	req := &ListUsersRequest{
		RoleFilter: UserRole(dynReq.Get(fields.ByName("role_filter")).Enum()),
		Limit:      int32(dynReq.Get(fields.ByName("limit")).Int()),
	}
	return srv.(UserServiceServer).ListUsers(req, &listUsersServer{stream})
}

// ── BatchCreateUsers (client-streaming) ───────────────────────

type batchCreateServer struct{ grpc.ServerStream }

func (s *batchCreateServer) Recv() (*CreateUserRequest, error) {
	dynReq := dynamicpb.NewMessage(CreateUserReqDesc)
	if err := s.ServerStream.RecvMsg(dynReq); err != nil {
		return nil, err
	}
	fields := CreateUserReqDesc.Fields()
	return &CreateUserRequest{
		Name:  dynReq.Get(fields.ByName("name")).String(),
		Email: dynReq.Get(fields.ByName("email")).String(),
	}, nil
}

func (s *batchCreateServer) SendAndClose(resp *BatchCreateUsersResponse) error {
	msg, err := marshalBatchCreateResponse(resp)
	if err != nil {
		return err
	}
	return s.ServerStream.SendMsg(msg)
}

func _UserService_BatchCreateUsers_Handler(srv interface{}, stream grpc.ServerStream) error {
	ss := &batchCreateServer{stream}
	resp, err := srv.(UserServiceServer).BatchCreateUsers(ss)
	if err != nil {
		return err
	}
	return ss.SendAndClose(resp)
}

// ── WatchUsers (bidi-streaming) ───────────────────────────────

type watchUsersServer struct{ grpc.ServerStream }

func (s *watchUsersServer) Send(resp *WatchUsersResponse) error {
	msg, err := marshalWatchUsersResponse(resp)
	if err != nil {
		return err
	}
	return s.ServerStream.SendMsg(msg)
}

func (s *watchUsersServer) Recv() (*WatchUsersRequest, error) {
	dynReq := dynamicpb.NewMessage(WatchUsersReqDesc)
	if err := s.ServerStream.RecvMsg(dynReq); err != nil {
		return nil, err
	}
	return &WatchUsersRequest{
		UserId: dynReq.Get(WatchUsersReqDesc.Fields().ByName("user_id")).String(),
	}, nil
}

func _UserService_WatchUsers_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(UserServiceServer).WatchUsers(&watchUsersServer{stream})
}

// ──────────────────────────────────────────────────────────────
// Marshal helpers: Go structs → dynamic proto messages
// ──────────────────────────────────────────────────────────────

func marshalUser(u *User) proto.Message {
	if u == nil {
		return dynamicpb.NewMessage(UserDesc)
	}
	msg := dynamicpb.NewMessage(UserDesc)
	fields := UserDesc.Fields()
	msg.Set(fields.ByName("id"), protoreflect.ValueOfString(u.Id))
	msg.Set(fields.ByName("name"), protoreflect.ValueOfString(u.Name))
	msg.Set(fields.ByName("email"), protoreflect.ValueOfString(u.Email))
	msg.Set(fields.ByName("role"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(u.Role)))

	if u.CreatedAt != nil {
		tsMsg := u.CreatedAt.ProtoReflect()
		msg.Set(fields.ByName("created_at"), protoreflect.ValueOfMessage(tsMsg))
	}
	return msg
}

func marshalGetUserResponse(resp *GetUserResponse) (proto.Message, error) {
	msg := dynamicpb.NewMessage(GetUserRespDesc)
	if resp.User != nil {
		userMsg := marshalUser(resp.User)
		msg.Set(GetUserRespDesc.Fields().ByName("user"), protoreflect.ValueOfMessage(userMsg.ProtoReflect()))
	}
	return msg, nil
}

func marshalCreateUserResponse(resp *CreateUserResponse) (proto.Message, error) {
	msg := dynamicpb.NewMessage(CreateUserRespDesc)
	if resp.User != nil {
		userMsg := marshalUser(resp.User)
		msg.Set(CreateUserRespDesc.Fields().ByName("user"), protoreflect.ValueOfMessage(userMsg.ProtoReflect()))
	}
	return msg, nil
}

func marshalBatchCreateResponse(resp *BatchCreateUsersResponse) (proto.Message, error) {
	msg := dynamicpb.NewMessage(BatchCreateRespDesc)
	fields := BatchCreateRespDesc.Fields()
	msg.Set(fields.ByName("created"), protoreflect.ValueOfInt32(resp.Created))
	if len(resp.Users) > 0 {
		list := msg.Mutable(fields.ByName("users")).List()
		for _, u := range resp.Users {
			list.Append(protoreflect.ValueOfMessage(marshalUser(u).ProtoReflect()))
		}
	}
	return msg, nil
}

func marshalWatchUsersResponse(resp *WatchUsersResponse) (proto.Message, error) {
	msg := dynamicpb.NewMessage(WatchUsersRespDesc)
	fields := WatchUsersRespDesc.Fields()
	msg.Set(fields.ByName("event"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(resp.Event)))
	if resp.User != nil {
		userMsg := marshalUser(resp.User)
		msg.Set(fields.ByName("user"), protoreflect.ValueOfMessage(userMsg.ProtoReflect()))
	}
	return msg, nil
}

// ──────────────────────────────────────────────────────────────
// gRPC client stub (used by demo mode and smoke tests)
// ──────────────────────────────────────────────────────────────

// DemoClient is a minimal gRPC client for UserService.
// It uses dynamic proto messages so no generated .pb.go code is needed.
type DemoClient struct {
	conn *grpc.ClientConn
}

// NewDemoClient creates a new DemoClient backed by conn.
func NewDemoClient(conn *grpc.ClientConn) *DemoClient {
	return &DemoClient{conn: conn}
}

// GetUser calls user.UserService/GetUser through conn using dynamic proto.
func (c *DemoClient) GetUser(ctx context.Context, req *GetUserRequest, opts ...grpc.CallOption) (*GetUserResponse, error) {
	dynReq := dynamicpb.NewMessage(GetUserReqDesc)
	dynReq.Set(GetUserReqDesc.Fields().ByName("user_id"), protoreflect.ValueOfString(req.UserId))

	dynResp := dynamicpb.NewMessage(GetUserRespDesc)
	if err := c.conn.Invoke(ctx, "/user.UserService/GetUser", dynReq, dynResp, opts...); err != nil {
		return nil, err
	}

	resp := &GetUserResponse{}
	userVal := dynResp.Get(GetUserRespDesc.Fields().ByName("user"))
	if userVal.IsValid() {
		resp.User = dynMessageToUser(userVal.Message())
	}
	return resp, nil
}

// CreateUser calls user.UserService/CreateUser through conn using dynamic proto.
func (c *DemoClient) CreateUser(ctx context.Context, req *CreateUserRequest, opts ...grpc.CallOption) (*CreateUserResponse, error) {
	dynReq := dynamicpb.NewMessage(CreateUserReqDesc)
	f := CreateUserReqDesc.Fields()
	dynReq.Set(f.ByName("name"), protoreflect.ValueOfString(req.Name))
	dynReq.Set(f.ByName("email"), protoreflect.ValueOfString(req.Email))

	dynResp := dynamicpb.NewMessage(CreateUserRespDesc)
	if err := c.conn.Invoke(ctx, "/user.UserService/CreateUser", dynReq, dynResp, opts...); err != nil {
		return nil, err
	}

	resp := &CreateUserResponse{}
	userVal := dynResp.Get(CreateUserRespDesc.Fields().ByName("user"))
	if userVal.IsValid() {
		resp.User = dynMessageToUser(userVal.Message())
	}
	return resp, nil
}

// ListUsers calls user.UserService/ListUsers (server-streaming) and returns all responses.
func (c *DemoClient) ListUsers(ctx context.Context, req *ListUsersRequest, opts ...grpc.CallOption) ([]*GetUserResponse, error) {
	dynReq := dynamicpb.NewMessage(ListUsersReqDesc)
	f := ListUsersReqDesc.Fields()
	dynReq.Set(f.ByName("role_filter"), protoreflect.ValueOfEnum(protoreflect.EnumNumber(req.RoleFilter)))
	dynReq.Set(f.ByName("limit"), protoreflect.ValueOfInt32(req.Limit))

	desc := &grpc.StreamDesc{ServerStreams: true}
	stream, err := c.conn.NewStream(ctx, desc, "/user.UserService/ListUsers", opts...)
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(dynReq); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}

	var results []*GetUserResponse
	for {
		dynResp := dynamicpb.NewMessage(GetUserRespDesc)
		if err := stream.RecvMsg(dynResp); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		resp := &GetUserResponse{}
		userVal := dynResp.Get(GetUserRespDesc.Fields().ByName("user"))
		if userVal.IsValid() {
			resp.User = dynMessageToUser(userVal.Message())
		}
		results = append(results, resp)
	}
	return results, nil
}

// dynMessageToUser converts a protoreflect.Message (the user field) to *User.
func dynMessageToUser(m protoreflect.Message) *User {
	if m == nil || !m.IsValid() {
		return nil
	}
	fields := UserDesc.Fields()
	return &User{
		Id:    m.Get(fields.ByName("id")).String(),
		Name:  m.Get(fields.ByName("name")).String(),
		Email: m.Get(fields.ByName("email")).String(),
		Role:  UserRole(m.Get(fields.ByName("role")).Enum()),
	}
}
