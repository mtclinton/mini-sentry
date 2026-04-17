//go:build linux

package main

// vfs_gofer.go — VFS client that speaks to a separate Gofer process.
//
// Implements the VFS interface by turning each method into one or more
// RPCs over the Sentry↔Gofer Unix socket. From the Sentry handlers'
// perspective, lookups/list/addFile look identical to the in-memory VFS —
// they just happen to cross a process boundary.
//
// Lookup is implemented as Open → Read → Close rather than a single
// "slurp this path" RPC. That keeps the wire protocol (which is supposed
// to resemble LISAFS) honest about how real filesystem access works, at
// the cost of a small RPC storm per open. Fine at our scale.

import (
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// GoferVFS is the Sentry-side client that implements VFS by RPC.
type GoferVFS struct {
	mu      sync.Mutex // serialize request/response; one outstanding RPC
	conn    io.ReadWriter
	nextID  uint64
	verbose bool
}

func NewGoferVFS(conn io.ReadWriter) *GoferVFS {
	return &GoferVFS{
		conn:    conn,
		verbose: os.Getenv("MINI_SENTRY_VERBOSE") != "",
	}
}

// rpc sends req and blocks for the matching response. Returns any transport
// error; application-level errors (e.g. ENOENT) come back in resp.Err.
func (v *GoferVFS) rpc(req *GoferRequest) (*GoferResponse, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.nextID++
	req.ID = v.nextID

	if v.verbose {
		switch req.Op {
		case OpOpen, OpListDir, OpAccess, OpAddFile:
			fmt.Fprintf(os.Stderr, "  [sentry→gofer] %s(%q)\n", opName(req.Op), req.Path)
		case OpRead:
			fmt.Fprintf(os.Stderr, "  [sentry→gofer] Read(fileID=%d, off=%d, n=%d)\n",
				req.FileID, req.Offset, req.Count)
		case OpClose, OpStat:
			fmt.Fprintf(os.Stderr, "  [sentry→gofer] %s(fileID=%d)\n", opName(req.Op), req.FileID)
		case OpFileCount:
			fmt.Fprintf(os.Stderr, "  [sentry→gofer] FileCount()\n")
		}
	}

	if err := writeFramed(v.conn, req); err != nil {
		return nil, err
	}
	var resp GoferResponse
	if err := readFramed(v.conn, &resp); err != nil {
		return nil, err
	}
	if resp.ID != req.ID {
		return nil, fmt.Errorf("gofer: id mismatch (want %d, got %d)", req.ID, resp.ID)
	}
	return &resp, nil
}

func (v *GoferVFS) AddFile(path string, data []byte) {
	_, err := v.rpc(&GoferRequest{Op: OpAddFile, Path: path, Data: data})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [sentry→gofer] AddFile(%q) failed: %v\n", path, err)
	}
}

// Lookup does Open, Reads the whole file, then Closes. Matches the
// InMemoryVFS Lookup signature (returning the full contents in one shot)
// so the Sentry handlers don't need to change.
func (v *GoferVFS) Lookup(path string) ([]byte, syscall.Errno) {
	openResp, err := v.rpc(&GoferRequest{Op: OpOpen, Path: path})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [sentry→gofer] Open(%q) transport error: %v\n", path, err)
		return nil, syscall.EIO
	}
	if openResp.Err != "" {
		return nil, goferErrToErrno(openResp.Err)
	}

	fileID := openResp.FileID
	size := openResp.Size

	// Read in chunks. Our messages use gob which buffers everything in
	// memory anyway, so a big chunk is fine — but keeping a cap here
	// makes the RPC trace in verbose mode more readable.
	const chunkSize = int64(4096)
	data := make([]byte, 0, size)
	offset := int64(0)
	for offset < size {
		n := chunkSize
		if offset+n > size {
			n = size - offset
		}
		rr, err := v.rpc(&GoferRequest{
			Op:     OpRead,
			FileID: fileID,
			Offset: offset,
			Count:  n,
		})
		if err != nil || rr.Err != "" {
			break
		}
		if len(rr.Data) == 0 {
			break
		}
		data = append(data, rr.Data...)
		offset += int64(len(rr.Data))
	}

	// Best-effort close — we already have the data; a close failure
	// leaks a handle on the gofer side but doesn't change the result.
	_, _ = v.rpc(&GoferRequest{Op: OpClose, FileID: fileID})
	return data, 0
}

// goferErrToErrno maps the symbolic error names the gofer returns back
// to concrete errno values. Anything unrecognized falls through to EIO.
func goferErrToErrno(name string) syscall.Errno {
	switch name {
	case "":
		return 0
	case "ENOENT":
		return syscall.ENOENT
	case "EACCES":
		return syscall.EACCES
	case "EBADF":
		return syscall.EBADF
	case "ENOTDIR":
		return syscall.ENOTDIR
	case "EINVAL":
		return syscall.EINVAL
	}
	return syscall.EIO
}

func (v *GoferVFS) ListDir(path string) []string {
	resp, err := v.rpc(&GoferRequest{Op: OpListDir, Path: path})
	if err != nil || resp.Err != "" {
		return nil
	}
	return resp.Entries
}

func (v *GoferVFS) FileCount() int {
	resp, err := v.rpc(&GoferRequest{Op: OpFileCount})
	if err != nil {
		return 0
	}
	return resp.Count
}
