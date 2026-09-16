// Package reflector discovers gRPC method descriptors via Server Reflection.
// Results are cached so each method is only looked up once per process, with
// a TTL so schema changes on the backend are eventually picked up without
// restarting Loom.
package reflector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bufbuild/protocompile"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
)

const DefaultCacheTTL = 5 * time.Minute

type cacheEntry struct {
	info    *MethodInfo
	fetchAt time.Time
}

// Tracks an in-progress fetch so concurrent callers for the same fullPath
// block on the first caller instead of each opening its own reflection
// connection (stampede protection).
type inflight struct {
	done chan struct{}
	info *MethodInfo
	err  error
}

type MethodInfo struct {
	FullMethod string
	Method     *desc.MethodDescriptor
	Input      *desc.MessageDescriptor
	Output     *desc.MessageDescriptor
}

type Reflector struct {
	conn     *grpc.ClientConn
	cacheTTL time.Duration

	mu      sync.RWMutex
	cache   map[string]*cacheEntry
	flights map[string]*inflight

	protoDir string // fallback source when reflection fails; set by AddProtoDir
}

func New(conn *grpc.ClientConn) *Reflector {
	return &Reflector{
		conn:     conn,
		cacheTTL: DefaultCacheTTL,
		cache:    make(map[string]*cacheEntry),
		flights:  make(map[string]*inflight),
	}
}

// Pass 0 to disable expiry (descriptors are cached forever once fetched).
func (r *Reflector) WithCacheTTL(ttl time.Duration) *Reflector {
	r.cacheTTL = ttl
	return r
}

func (r *Reflector) AddProtoDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading proto dir: %w", err)
	}
	if !dirHasProtoFiles(entries) {
		return fmt.Errorf("no .proto files found in %q", dir)
	}
	r.mu.Lock()
	r.protoDir = filepath.Clean(dir)
	r.mu.Unlock()
	return nil
}

func dirHasProtoFiles(entries []os.DirEntry) bool {
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".proto") {
			return true
		}
	}
	return false
}

// Lookup order: fresh cache hit, then server reflection (stampede-protected
// so concurrent callers share one fetch per cache miss), then the proto-dir
// fallback if reflection fails and one was registered. A stale cache entry
// is returned immediately while a refresh runs in the background, so an
// active call is never blocked on a re-fetch of a descriptor that still works.
func (r *Reflector) Resolve(ctx context.Context, fullPath string) (*MethodInfo, error) {
	r.mu.RLock()
	entry, cached := r.cache[fullPath]
	r.mu.RUnlock()

	if cached {
		if r.cacheTTL == 0 || time.Since(entry.fetchAt) < r.cacheTTL {
			return entry.info, nil
		}
		go r.refreshCache(fullPath) //nolint:errcheck
		return entry.info, nil
	}

	serviceName, methodName, err := splitFullPath(fullPath)
	if err != nil {
		return nil, err
	}
	return r.fetchWithSingleflight(ctx, fullPath, serviceName, methodName)
}

func splitFullPath(fullPath string) (service, method string, err error) {
	parts := strings.SplitN(strings.TrimPrefix(fullPath, "/"), "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid gRPC path %q — expected /Package.Service/Method", fullPath)
	}
	return parts[0], parts[1], nil
}

func (r *Reflector) refreshCache(fullPath string) {
	svc, method, err := splitFullPath(fullPath)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := r.resolveFromSources(ctx, svc, method, fullPath)
	if err != nil {
		return // keep the stale entry; the next call will retry
	}
	r.mu.Lock()
	r.cache[fullPath] = &cacheEntry{info: info, fetchAt: time.Now()}
	r.mu.Unlock()
}

func (r *Reflector) fetchWithSingleflight(
	ctx context.Context,
	fullPath, serviceName, methodName string,
) (*MethodInfo, error) {
	r.mu.Lock()
	// Another goroutine may have populated the cache while we waited for the lock.
	if entry, ok := r.cache[fullPath]; ok {
		r.mu.Unlock()
		return entry.info, nil
	}

	if fl, ok := r.flights[fullPath]; ok {
		r.mu.Unlock()
		select {
		case <-fl.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return fl.info, fl.err
	}

	fl := &inflight{done: make(chan struct{})}
	r.flights[fullPath] = fl
	r.mu.Unlock()

	info, err := r.resolveFromSources(ctx, serviceName, methodName, fullPath)

	fl.info, fl.err = info, err
	close(fl.done)

	r.mu.Lock()
	delete(r.flights, fullPath)
	if err == nil {
		r.cache[fullPath] = &cacheEntry{info: info, fetchAt: time.Now()}
	}
	r.mu.Unlock()

	return info, err
}

func (r *Reflector) resolveFromSources(
	ctx context.Context,
	svc, method, full string,
) (*MethodInfo, error) {
	info, reflectErr := r.fetchFromServer(ctx, svc, method, full)
	if reflectErr == nil {
		return info, nil
	}

	r.mu.RLock()
	dir := r.protoDir
	r.mu.RUnlock()

	if dir == "" {
		return nil, fmt.Errorf("%w\n  Tip: use -proto-dir ./schemas if reflection is disabled on this server", reflectErr)
	}

	info, protoErr := r.fetchFromProtoDir(ctx, dir, svc, method, full)
	if protoErr != nil {
		return nil, fmt.Errorf(
			"proto-dir fallback failed: %w (reflection error was: %s)",
			protoErr, reflectErr.Error(),
		)
	}
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

func (r *Reflector) fetchFromProtoDir(
	ctx context.Context,
	dir, svc, method, full string,
) (*MethodInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading proto dir %q: %w", dir, err)
	}

	var protoFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".proto") {
			protoFiles = append(protoFiles, e.Name())
		}
	}
	if len(protoFiles) == 0 {
		return nil, fmt.Errorf("no .proto files in %q", dir)
	}

	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(
			&protocompile.SourceResolver{ImportPaths: []string{dir}},
		),
	}

	linked, err := compiler.Compile(ctx, protoFiles...)
	if err != nil {
		return nil, fmt.Errorf("compiling proto files in %q: %w", dir, err)
	}

	for i := 0; i < len(linked); i++ {
		jDesc, wrapErr := desc.WrapFile(linked[i]) // wrap into the jhump desc types the rest of Loom expects
		if wrapErr != nil {
			continue
		}
		jSvc := findService(jDesc, svc)
		if jSvc == nil {
			continue
		}
		jMethod := jSvc.FindMethodByName(method)
		if jMethod == nil {
			return nil, fmt.Errorf("method %q not found in service %q (proto-dir)", method, svc)
		}
		return &MethodInfo{
			FullMethod: full,
			Method:     jMethod,
			Input:      jMethod.GetInputType(),
			Output:     jMethod.GetOutputType(),
		}, nil
	}

	return nil, fmt.Errorf("service %q not found in any .proto file in %q", svc, dir)
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
