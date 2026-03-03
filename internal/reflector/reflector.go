// Package reflector discovers gRPC method descriptors via Server Reflection.
// Results are cached so each method is only looked up once per process.
package reflector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
)

// MethodInfo holds resolved descriptors for one RPC method.
type MethodInfo struct {
	FullMethod string
	Method     *desc.MethodDescriptor
	Input      *desc.MessageDescriptor
	Output     *desc.MessageDescriptor
}

// Reflector resolves gRPC method descriptors via Server Reflection,
// caching after the first successful lookup.
type Reflector struct {
	conn     *grpc.ClientConn
	mu       sync.RWMutex
	cache    map[string]*MethodInfo
	protoDir string // set by AddProtoDir; informational only for now
}

// New creates a Reflector backed by conn.
func New(conn *grpc.ClientConn) *Reflector {
	return &Reflector{
		conn:  conn,
		cache: make(map[string]*MethodInfo),
	}
}

// AddProtoDir registers a directory of .proto files as a fallback source.
// The directory must exist and contain at least one .proto file.
// Returns an error only if the directory cannot be read.
func (r *Reflector) AddProtoDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading proto dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".proto") {
			count++
		}
	}
	if count == 0 {
		return fmt.Errorf("no .proto files found in %q", dir)
	}
	r.mu.Lock()
	r.protoDir = filepath.Clean(dir)
	r.mu.Unlock()
	return nil
}

// Resolve returns the MethodInfo for fullPath (e.g. "/user.UserService/GetUser").
// Results are cached. Returns an error if reflection fails and no proto fallback
// matched.
func (r *Reflector) Resolve(ctx context.Context, fullPath string) (*MethodInfo, error) {
	r.mu.RLock()
	if info, ok := r.cache[fullPath]; ok {
		r.mu.RUnlock()
		return info, nil
	}
	r.mu.RUnlock()

	parts := strings.SplitN(strings.TrimPrefix(fullPath, "/"), "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid gRPC path %q — expected /Package.Service/Method", fullPath)
	}
	serviceName, methodName := parts[0], parts[1]

	info, err := r.fetchFromServer(ctx, serviceName, methodName, fullPath)
	if err != nil {
		r.mu.RLock()
		hasDir := r.protoDir != ""
		r.mu.RUnlock()
		hint := ""
		if !hasDir {
			hint = "\n  Tip: use -proto-dir ./schemas if reflection is disabled on this server"
		}
		return nil, fmt.Errorf("%w%s", err, hint)
	}

	r.mu.Lock()
	r.cache[fullPath] = info
	r.mu.Unlock()
	return info, nil
}

func (r *Reflector) fetchFromServer(ctx context.Context, svc, method, full string) (*MethodInfo, error) {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	client := grpcreflect.NewClientAuto(tctx, r.conn)
	defer client.Reset()

	fileDesc, err := client.FileContainingSymbol(svc)
	if err != nil {
		return nil, fmt.Errorf("gRPC reflection failed for %q: %w\n  → Is reflection registered on your backend?", svc, err)
	}

	svcDesc := findService(fileDesc, svc)
	if svcDesc == nil {
		return nil, fmt.Errorf("service %q not found in reflected file", svc)
	}
	methodDesc := svcDesc.FindMethodByName(method)
	if methodDesc == nil {
		return nil, fmt.Errorf("method %q not found in service %q", method, svc)
	}
	return &MethodInfo{
		FullMethod: full,
		Method:     methodDesc,
		Input:      methodDesc.GetInputType(),
		Output:     methodDesc.GetOutputType(),
	}, nil
}

func findService(fd *desc.FileDescriptor, name string) *desc.ServiceDescriptor {
	for _, s := range fd.GetServices() {
		if s.GetFullyQualifiedName() == name {
			return s
		}
	}
	for _, dep := range fd.GetDependencies() {
		if found := findService(dep, name); found != nil {
			return found
		}
	}
	return nil
}
