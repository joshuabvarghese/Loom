// Package reflector discovers gRPC method descriptors via Server Reflection.
// Results are cached so each method is only looked up once per process, with a
// configurable TTL to protect against stale descriptors after backend redeploys.
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

// DefaultCacheTTL is how long a cached descriptor is considered fresh.
// After this duration the next Resolve call will re-fetch from the backend
// so that schema changes (new fields, renamed enums) are picked up
// without restarting Loom.
const DefaultCacheTTL = 5 * time.Minute

// cacheEntry wraps a MethodInfo with its fetch timestamp.
type cacheEntry struct {
	info    *MethodInfo
	fetchAt time.Time
}

// inflight tracks an in-progress fetch so concurrent callers for the same
// fullPath block on the first caller rather than each spawning their own
// reflection connection (stampede protection).
type inflight struct {
	done chan struct{}
	info *MethodInfo
	err  error
}

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
	cacheTTL time.Duration

	mu      sync.RWMutex
	cache   map[string]*cacheEntry
	flights map[string]*inflight // in-progress fetches

	protoDir string // set by AddProtoDir; used as fallback when reflection fails
}

// New creates a Reflector backed by conn.
func New(conn *grpc.ClientConn) *Reflector {
	return &Reflector{
		conn:     conn,
		cacheTTL: DefaultCacheTTL,
		cache:    make(map[string]*cacheEntry),
		flights:  make(map[string]*inflight),
	}
}

// WithCacheTTL overrides the descriptor cache TTL. Pass 0 to disable
// expiry (equivalent to the old always-cached behaviour).
func (r *Reflector) WithCacheTTL(ttl time.Duration) *Reflector {
	r.cacheTTL = ttl
	return r
}

// AddProtoDir registers a directory of .proto files as a fallback source
// used when server reflection is unavailable. The directory must exist and
// contain at least one .proto file.
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
//
// Lookup order:
//  1. Fresh cache hit (within cacheTTL).
//  2. Server reflection (with stampede-protection so concurrent callers share
//     one reflection connection per cache-miss).
//  3. Proto-dir fallback (if AddProtoDir was called and reflection failed).
//
// Stale cache entries (older than cacheTTL) are re-fetched in the background;
// the stale value is returned immediately so callers are never blocked on a
// re-fetch of a descriptor that still works.
func (r *Reflector) Resolve(ctx context.Context, fullPath string) (*MethodInfo, error) {
	// 1. Cache lookup
	r.mu.RLock()
	entry, cached := r.cache[fullPath]
	r.mu.RUnlock()

	if cached {
		fresh := r.cacheTTL == 0 || time.Since(entry.fetchAt) < r.cacheTTL
		if fresh {
			return entry.info, nil
		}
		// Stale: return the current value immediately while refreshing in
		// the background, so active calls are never blocked by a re-fetch.
		go r.refreshCache(fullPath) //nolint:errcheck
		return entry.info, nil
	}

	// 2. Parse fullPath
	parts := strings.SplitN(strings.TrimPrefix(fullPath, "/"), "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid gRPC path %q — expected /Package.Service/Method", fullPath)
	}
	serviceName, methodName := parts[0], parts[1]

	// 3. Stampede-protected fetch
	return r.fetchWithSingleflight(ctx, fullPath, serviceName, methodName)
}

// refreshCache re-fetches the descriptor for fullPath and updates the cache.
// Called in a goroutine for stale-while-revalidate behaviour.
func (r *Reflector) refreshCache(fullPath string) {
	parts := strings.SplitN(strings.TrimPrefix(fullPath, "/"), "/", 2)
	if len(parts) != 2 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := r.resolveFromSources(ctx, parts[0], parts[1], fullPath)
	if err != nil {
		return // keep the stale entry; next call will retry
	}
	r.mu.Lock()
	r.cache[fullPath] = &cacheEntry{info: info, fetchAt: time.Now()}
	r.mu.Unlock()
}

// fetchWithSingleflight ensures that concurrent cache-miss callers for the
// same fullPath share a single reflection fetch rather than each spawning
// their own connection (stampede protection).
func (r *Reflector) fetchWithSingleflight(
	ctx context.Context,
	fullPath, serviceName, methodName string,
) (*MethodInfo, error) {
	r.mu.Lock()
	// Double-check: another goroutine may have populated the cache while we
	// were waiting for the write lock.
	if entry, ok := r.cache[fullPath]; ok {
		r.mu.Unlock()
		return entry.info, nil
	}

	// Is there already an in-progress fetch for this path?
	if fl, ok := r.flights[fullPath]; ok {
		r.mu.Unlock()
		select {
		case <-fl.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return fl.info, fl.err
	}

	// We are the leader; register the inflight record.
	fl := &inflight{done: make(chan struct{})}
	r.flights[fullPath] = fl
	r.mu.Unlock()

	// Perform the actual fetch (reflection first, then proto-dir fallback).
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

// resolveFromSources tries server reflection first and falls back to the
// proto-dir parser if reflection fails and a directory has been registered.
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

// fetchFromServer fetches the method descriptor via gRPC Server Reflection.
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

// fetchFromProtoDir parses .proto files in dir using protocompile and resolves
// the requested service/method. This is the fallback path for backends that
// have server reflection disabled in production.
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

	// Search compiled files for the requested service.
	for i := 0; i < len(linked); i++ {
		f := linked[i]

		// Wrap in jhump desc types that the rest of Loom expects.
		jDesc, wrapErr := desc.WrapFile(f)
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
