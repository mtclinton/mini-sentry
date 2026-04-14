//go:build linux

package main

// gofer.go — The Gofer process (maps to gVisor's runsc-gofer).
//
// The Gofer is the filesystem security boundary. It runs as a separate
// process with its own view of the world, and the Sentry has to ask it
// (over a Unix socket) for any file operation. If the Sentry is
// compromised, it still can't access any file the Gofer doesn't serve.
//
// In gVisor, the Gofer uses LISAFS (formerly 9P) over a pair of Unix
// sockets, tracks host FDs by numeric ID, and can be further locked down
// with its own seccomp filter plus a chroot. Ours is the same shape: a
// request/response loop over a socket, a file table keyed by ID, and an
// optional host directory that's mounted read-only.
//
// Bootstrap: main.go re-execs /proc/self/exe with MINI_SENTRY_GOFER=1
// and the gofer side of a socketpair mapped to fd 3. RunGoferBootstrap
// detects the env var, takes over, and never returns.

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	goferEnvVar       = "MINI_SENTRY_GOFER"
	goferRootEnvVar   = "MINI_SENTRY_GOFER_ROOT"
	goferDenyEnvVar   = "MINI_SENTRY_GOFER_DENY"
	goferMountsEnvVar = "MINI_SENTRY_GOFER_MOUNTS"

	// goferSockFD is the fd that the parent maps the child end of the
	// socketpair onto when it re-execs us.
	goferSockFD = 3
)

// RunGoferBootstrap is called at the very top of main(). If we were
// launched as a gofer child (MINI_SENTRY_GOFER=1 in env), we enter the
// service loop and never return. Otherwise we return immediately and
// main continues as the Sentry.
func RunGoferBootstrap() {
	if os.Getenv(goferEnvVar) == "" {
		return
	}

	f := os.NewFile(uintptr(goferSockFD), "gofer-sock")
	if f == nil {
		fmt.Fprintln(os.Stderr, "[gofer] fd 3 not usable")
		os.Exit(1)
	}
	conn, err := net.FileConn(f)
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gofer] net.FileConn: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	g := newGoferServer(os.Getenv(goferRootEnvVar))
	g.denies = parseDenyList(os.Getenv(goferDenyEnvVar))
	g.mounts = sortMountsByGuestLen(deserializeMounts(os.Getenv(goferMountsEnvVar)))
	seedDefaults(g.addFile)

	if os.Getenv("MINI_SENTRY_VERBOSE") != "" {
		fmt.Fprintf(os.Stderr, "[gofer] ready: %d virtual files, root=%q, mounts=%d, deny=%v\n",
			len(g.files), g.root, len(g.mounts), g.denies)
	}

	g.Serve(conn)
	os.Exit(0)
}

// goferServer holds the gofer's private view of the filesystem: the
// in-memory virtual files, a file table for open handles, a list of
// mounts exposed to the guest, and an optional global root
// (--gofer-root, back-compat shorthand for `--mount /HOST:/:ro`).
type goferServer struct {
	files     map[string][]byte
	dirs      map[string][]string
	openFiles map[uint64]*goferOpenFile
	nextID    uint64
	root      string   // optional host dir served read-only (legacy)
	mounts    []Mount  // --mount entries, longest-guest-prefix first
	denies    []string // guest-path prefixes that always get EACCES
}

// parseDenyList turns "a,b,c" into ["/a", "/b", "/c"] with cleaning.
// Empty entries are dropped.
func parseDenyList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

// isDenied returns true if the guest path falls under any configured
// deny prefix. Matching is path-component-wise so "/foo" denies "/foo"
// and "/foo/bar" but not "/foobar".
func (g *goferServer) isDenied(path string) bool {
	p := filepath.Clean(path)
	for _, d := range g.denies {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

type goferOpenFile struct {
	path string
	data []byte
}

func newGoferServer(root string) *goferServer {
	abs := root
	if root != "" {
		if a, err := filepath.Abs(root); err == nil {
			abs = a
		}
	}
	return &goferServer{
		files:     make(map[string][]byte),
		dirs:      make(map[string][]string),
		openFiles: make(map[uint64]*goferOpenFile),
		nextID:    1,
		root:      abs,
	}
}

func (g *goferServer) addFile(path string, data []byte) {
	path = filepath.Clean(path)
	g.files[path] = data
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	for _, n := range g.dirs[dir] {
		if n == name {
			return
		}
	}
	g.dirs[dir] = append(g.dirs[dir], name)
}

// lookup resolves a guest path to file bytes. Virtual files always win
// (so /etc/hostname stays "mini-sentry-sandbox" even with --gofer-root=/).
// Otherwise, when --gofer-root is set, we fall through to the host
// directory as a read-only passthrough — subject to two escape checks
// (literal path traversal and symlink resolution) and the deny list.
func (g *goferServer) lookup(path string) ([]byte, bool) {
	path = filepath.Clean(path)
	if d, ok := g.files[path]; ok {
		return d, true
	}
	real, ok := g.resolveHost(path)
	if !ok {
		return nil, false
	}
	info, err := os.Stat(real)
	if err != nil || info.IsDir() {
		return nil, false
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return nil, false
	}
	return data, true
}

// resolveHost maps a guest path to a real host path, refusing anything
// that escapes the mount's host root via either literal ".." components
// or a symlink. Returns ("", false) if the path can't be safely served.
//
// Lookup order:
//  1. --mount entries, longest guest-prefix first.
//  2. --gofer-root (legacy).
func (g *goferServer) resolveHost(path string) (string, bool) {
	cleaned := filepath.Clean(path)

	// Try --mount entries first. They're sorted longest-first so
	// /usr/lib/foo hits a /usr/lib mount before a / mount.
	for _, m := range g.mounts {
		mapped, ok := resolveWithinHostRoot(m.Host, m.Guest, cleaned)
		if ok {
			return mapped, true
		}
	}
	if g.root == "" {
		return "", false
	}
	real := filepath.Join(g.root, cleaned)
	// Literal escape: "/foo/../../etc/passwd".
	rel, err := filepath.Rel(g.root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	// Symlink escape: /tmp/link -> /etc/passwd with --gofer-root=/tmp.
	// Resolve both sides and re-check the relation. If the target
	// doesn't exist EvalSymlinks errors — treat that as "not found"
	// rather than letting the raw join leak through.
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		return "", false
	}
	resolvedRoot, err := filepath.EvalSymlinks(g.root)
	if err != nil {
		return "", false
	}
	rel2, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return "", false
	}
	return resolved, true
}

func (g *goferServer) listDir(path string) []string {
	path = filepath.Clean(path)
	var entries []string
	seen := map[string]bool{}
	for _, n := range g.dirs[path] {
		if !seen[n] {
			entries = append(entries, n)
			seen[n] = true
		}
	}
	prefix := path
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	for fp := range g.files {
		if strings.HasPrefix(fp, prefix) {
			rest := fp[len(prefix):]
			parts := strings.SplitN(rest, "/", 2)
			name := parts[0]
			if !seen[name] {
				entries = append(entries, name)
				seen[name] = true
			}
		}
	}
	// Merge in host directory entries from --mount entries and the
	// legacy --gofer-root. Virtual files win on name collisions (seen
	// already captures them), and denied children are filtered out so
	// ls can't see what cat can't open.
	if real, ok := g.resolveHost(path); ok {
		if hostEntries, err := os.ReadDir(real); err == nil {
			for _, e := range hostEntries {
				name := e.Name()
				if seen[name] {
					continue
				}
				child := filepath.Join(path, name)
				if g.isDenied(child) {
					continue
				}
				entries = append(entries, name)
				seen[name] = true
			}
		}
	}
	// Mount points whose guest path is a direct child of `path` should
	// show up in its listing even if their host side isn't resolvable
	// or the mount host dir is empty. Example: `--mount /lib:/lib:ro`
	// means `/` must show "lib" whether or not /lib (host) exists.
	for _, m := range g.mounts {
		if filepath.Dir(m.Guest) != path {
			continue
		}
		name := filepath.Base(m.Guest)
		if seen[name] {
			continue
		}
		entries = append(entries, name)
		seen[name] = true
	}
	if len(entries) == 0 {
		return nil
	}
	result := []string{".", ".."}
	result = append(result, entries...)
	return result
}

// Serve is the request/response loop. Returns when the Sentry closes
// its end of the socket.
func (g *goferServer) Serve(conn io.ReadWriter) {
	verbose := os.Getenv("MINI_SENTRY_VERBOSE") != ""
	for {
		var req GoferRequest
		if err := readFramed(conn, &req); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed") {
				fmt.Fprintf(os.Stderr, "[gofer] read: %v\n", err)
			}
			return
		}
		resp := g.handle(&req)
		resp.ID = req.ID
		if verbose {
			g.logOp(&req, resp)
		}
		if err := writeFramed(conn, resp); err != nil {
			fmt.Fprintf(os.Stderr, "[gofer] write: %v\n", err)
			return
		}
	}
}

func (g *goferServer) handle(req *GoferRequest) *GoferResponse {
	resp := &GoferResponse{}
	switch req.Op {
	case OpAddFile:
		g.addFile(req.Path, req.Data)

	case OpOpen:
		if g.isDenied(req.Path) {
			resp.Err = "EACCES"
			return resp
		}
		data, ok := g.lookup(req.Path)
		if !ok {
			resp.Err = "ENOENT"
			return resp
		}
		id := g.nextID
		g.nextID++
		g.openFiles[id] = &goferOpenFile{path: req.Path, data: data}
		resp.FileID = id
		resp.Size = int64(len(data))
		resp.Mode = 0100644

	case OpRead:
		f, ok := g.openFiles[req.FileID]
		if !ok {
			resp.Err = "EBADF"
			return resp
		}
		if req.Offset >= int64(len(f.data)) {
			return resp // EOF: empty data
		}
		end := req.Offset + req.Count
		if end > int64(len(f.data)) {
			end = int64(len(f.data))
		}
		chunk := make([]byte, end-req.Offset)
		copy(chunk, f.data[req.Offset:end])
		resp.Data = chunk

	case OpClose:
		delete(g.openFiles, req.FileID)

	case OpStat:
		f, ok := g.openFiles[req.FileID]
		if !ok {
			resp.Err = "EBADF"
			return resp
		}
		resp.Size = int64(len(f.data))
		resp.Mode = 0100644

	case OpListDir:
		entries := g.listDir(req.Path)
		if entries == nil {
			resp.Err = "ENOTDIR"
			return resp
		}
		resp.Entries = entries

	case OpAccess:
		if g.isDenied(req.Path) {
			resp.Err = "EACCES"
			return resp
		}
		if _, ok := g.lookup(req.Path); ok {
			return resp
		}
		if g.listDir(req.Path) != nil {
			return resp
		}
		resp.Err = "ENOENT"

	case OpFileCount:
		resp.Count = len(g.files)

	default:
		resp.Err = "EINVAL"
	}
	return resp
}

// logOp prints one line per RPC under MINI_SENTRY_VERBOSE=1.
func (g *goferServer) logOp(req *GoferRequest, resp *GoferResponse) {
	switch req.Op {
	case OpOpen:
		if resp.Err != "" {
			fmt.Fprintf(os.Stderr, "[gofer] Open(%q) -> %s\n", req.Path, resp.Err)
		} else {
			fmt.Fprintf(os.Stderr, "[gofer] Open(%q) -> fileID=%d, size=%d\n", req.Path, resp.FileID, resp.Size)
		}
	case OpRead:
		fmt.Fprintf(os.Stderr, "[gofer] Read(fileID=%d, offset=%d, count=%d) -> %d bytes\n",
			req.FileID, req.Offset, req.Count, len(resp.Data))
	case OpClose:
		fmt.Fprintf(os.Stderr, "[gofer] Close(fileID=%d)\n", req.FileID)
	case OpStat:
		fmt.Fprintf(os.Stderr, "[gofer] Stat(fileID=%d) -> size=%d\n", req.FileID, resp.Size)
	case OpListDir:
		fmt.Fprintf(os.Stderr, "[gofer] ListDir(%q) -> %d entries\n", req.Path, len(resp.Entries))
	case OpAccess:
		result := "ok"
		if resp.Err != "" {
			result = resp.Err
		}
		fmt.Fprintf(os.Stderr, "[gofer] Access(%q) -> %s\n", req.Path, result)
	case OpFileCount:
		fmt.Fprintf(os.Stderr, "[gofer] FileCount() -> %d\n", resp.Count)
	case OpAddFile:
		fmt.Fprintf(os.Stderr, "[gofer] AddFile(%q, %d bytes)\n", req.Path, len(req.Data))
	default:
		fmt.Fprintf(os.Stderr, "[gofer] %s -> %s\n", opName(req.Op), resp.Err)
	}
}

// startGofer is called from main.go to spawn the gofer child, and returns
// a GoferVFS client connected to it. The returned cleanup function closes
// the socket and reaps the child.
func startGofer(goferRoot, goferDeny string, mounts []Mount) (*GoferVFS, func(), error) {
	sp, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentFD, childFD := sp[0], sp[1]

	selfExe, err := os.Executable()
	if err != nil {
		syscall.Close(parentFD)
		syscall.Close(childFD)
		return nil, nil, fmt.Errorf("os.Executable: %w", err)
	}

	env := make([]string, 0, len(os.Environ())+4)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, goferEnvVar+"=") ||
			strings.HasPrefix(e, goferRootEnvVar+"=") ||
			strings.HasPrefix(e, goferDenyEnvVar+"=") ||
			strings.HasPrefix(e, goferMountsEnvVar+"=") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, goferEnvVar+"=1")
	if goferRoot != "" {
		env = append(env, goferRootEnvVar+"="+goferRoot)
	}
	if goferDeny != "" {
		env = append(env, goferDenyEnvVar+"="+goferDeny)
	}
	if m := serializeMounts(mounts); m != "" {
		env = append(env, goferMountsEnvVar+"="+m)
	}

	pid, err := syscall.ForkExec(selfExe, []string{"mini-sentry-gofer"}, &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2, uintptr(childFD)},
		Env:   env,
	})
	syscall.Close(childFD)
	if err != nil {
		syscall.Close(parentFD)
		return nil, nil, fmt.Errorf("fork gofer: %w", err)
	}

	parentFile := os.NewFile(uintptr(parentFD), "gofer-sock-parent")
	conn, err := net.FileConn(parentFile)
	parentFile.Close() // FileConn dup'd the fd
	if err != nil {
		// best-effort: tear down the child
		syscall.Kill(pid, syscall.SIGKILL)
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
		return nil, nil, fmt.Errorf("net.FileConn: %w", err)
	}

	client := NewGoferVFS(conn)

	cleanup := func() {
		conn.Close()
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
	}
	return client, cleanup, nil
}

// resolveWithinHostRoot maps guestPath (inside the guest's view) to a
// real host path inside hostRoot, rejecting literal ".." escapes and
// symlink escapes. Returns ("", false) when guestPath falls outside
// the mount's guest subtree or points outside its host subtree.
//
// Pulled out as a free function so both --mount entries and the legacy
// --gofer-root go through the same escape-check logic.
func resolveWithinHostRoot(hostRoot, guestRoot, guestPath string) (string, bool) {
	// Does guestPath live under guestRoot?
	rel, err := filepath.Rel(guestRoot, guestPath)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	real := filepath.Join(hostRoot, rel)

	// Literal escape (redundant given Rel above, but cheap insurance).
	relFromHost, err := filepath.Rel(hostRoot, real)
	if err != nil || relFromHost == ".." ||
		strings.HasPrefix(relFromHost, ".."+string(filepath.Separator)) {
		return "", false
	}
	// Symlink escape.
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		return "", false
	}
	resolvedRoot, err := filepath.EvalSymlinks(hostRoot)
	if err != nil {
		return "", false
	}
	rel2, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel2 == ".." ||
		strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return "", false
	}
	return resolved, true
}
