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
	"fmt"
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

	UserDesc          protoreflect.MessageDescriptor
	GetUserReqDesc    protoreflect.MessageDescriptor
	GetUserRespDesc   protoreflect.MessageDescriptor
	CreateUserReqDesc protoreflect.MessageDescriptor
	CreateUserRespDesc protoreflect.MessageDescriptor

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
	fdp := &descriptorpb.FileDescriptorProto{
		Name:       ptr("user.proto"),
		Package:    ptr("user"),
		Dependency: []string{"google/protobuf/timestamp.proto"},
		Options:    &descriptorpb.FileOptions{GoPackage: ptr("github.com/joshuabvarghese/loom/testserver/gen")},
		Syntax:     ptr("proto3"),

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
		},

		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: ptr("UserService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{Name: ptr("GetUser"), InputType: ptr(".user.GetUserRequest"), OutputType: ptr(".user.GetUserResponse")},
					{Name: ptr("CreateUser"), InputType: ptr(".user.CreateUserRequest"), OutputType: ptr(".user.CreateUserResponse")},
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
	UserRoleDesc = UserDesc.Enums().ByName("Role")

	// Register all message types so proto.Marshal / Unmarshal can find them
	registerType(fd.Messages().ByName("User"))
	registerType(fd.Messages().ByName("GetUserRequest"))
	registerType(fd.Messages().ByName("GetUserResponse"))
	registerType(fd.Messages().ByName("CreateUserRequest"))
	registerType(fd.Messages().ByName("CreateUserResponse"))
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
// gRPC service types (mirrors what protoc-gen-go-grpc generates)
// ──────────────────────────────────────────────────────────────

// User is a dynamic wrapper so test server code can use field helpers.
type User struct {
	Id        string
	Name      string
	Email     string
	Role      UserRole
	CreatedAt *timestamppb.Timestamp
}

// UserRole mirrors the enum values.
type UserRole int32

const (
	User_ROLE_UNSPECIFIED UserRole = 0
	User_ROLE_ADMIN       UserRole = 1
	User_ROLE_EDITOR      UserRole = 2
	User_ROLE_VIEWER      UserRole = 3
)

// GetUserRequest is the decoded request for GetUser.
type GetUserRequest struct{ UserId string }

// GetUserResponse wraps the response User.
type GetUserResponse struct{ User *User }

// CreateUserRequest holds new user fields.
type CreateUserRequest struct{ Name, Email string }

// CreateUserResponse wraps the created User.
type CreateUserResponse struct{ User *User }

// ──────────────────────────────────────────────────────────────
// gRPC server interface & registration
// ──────────────────────────────────────────────────────────────

// UserServiceServer is the server-side interface for UserService.
type UserServiceServer interface {
	GetUser(req *GetUserRequest) (*GetUserResponse, error)
	CreateUser(req *CreateUserRequest) (*CreateUserResponse, error)
}

// UnimplementedUserServiceServer provides default (unimplemented) handlers.
type UnimplementedUserServiceServer struct{}

func (UnimplementedUserServiceServer) GetUser(*GetUserRequest) (*GetUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetUser not implemented")
}
func (UnimplementedUserServiceServer) CreateUser(*CreateUserRequest) (*CreateUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateUser not implemented")
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
		{
			MethodName: "GetUser",
			Handler:    _UserService_GetUser_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _UserService_CreateUser_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "user.proto",
}

// ──────────────────────────────────────────────────────────────
// gRPC method handlers — decode dynamic proto → call server
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
	handler := func(s interface{}, r interface{}) (interface{}, error) {
		return s.(UserServiceServer).GetUser(r.(*GetUserRequest))
	}
	var resp *GetUserResponse
	var err error
	if interceptor == nil {
		resp, err = srv.(UserServiceServer).GetUser(req)
	} else {
		result, iErr := interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
			return handler(srv, req)
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
