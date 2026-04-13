package main

// gofer_proto.go — Wire protocol between the Sentry and the Gofer.
//
// Framing: 4-byte big-endian length, followed by a gob-encoded message.
// Each request carries a monotonically increasing ID; the response echoes
// it back. In practice we issue one request at a time and block until the
// response comes back, so the ID is really there for illustration —
// gVisor's LISAFS pipelines requests over the same socket and uses the
// tag/ID to demultiplex. Our version keeps the shape without the async
// machinery.
//
// Messages are plain structs. Using gob means we don't have to worry about
// base64-encoding []byte blobs the way JSON would force us to.

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"
)

// GoferOp identifies a request type. Mirrors the small subset of LISAFS
// operations our Sentry needs.
type GoferOp uint8

const (
	OpInvalid GoferOp = iota
	OpAddFile
	OpOpen
	OpRead
	OpClose
	OpStat
	OpListDir
	OpAccess
	OpFileCount
)

func opName(op GoferOp) string {
	switch op {
	case OpAddFile:
		return "AddFile"
	case OpOpen:
		return "Open"
	case OpRead:
		return "Read"
	case OpClose:
		return "Close"
	case OpStat:
		return "Stat"
	case OpListDir:
		return "ListDir"
	case OpAccess:
		return "Access"
	case OpFileCount:
		return "FileCount"
	}
	return "Unknown"
}

// GoferRequest is the union of every operation's inputs. Irrelevant fields
// stay at their zero values; gob encodes them cheaply.
type GoferRequest struct {
	ID     uint64
	Op     GoferOp
	Path   string
	Data   []byte
	FileID uint64
	Offset int64
	Count  int64
}

// GoferResponse is the union of every operation's outputs. Err is a
// symbolic errno name (e.g., "ENOENT") so the Sentry side can map back
// to a concrete errno without threading syscall.Errno through gob.
type GoferResponse struct {
	ID      uint64
	FileID  uint64
	Size    int64
	Mode    uint32
	Data    []byte
	Entries []string
	Count   int
	Err     string
}

// writeFramed encodes v with gob and prepends a 4-byte big-endian length.
func writeFramed(w io.Writer, v interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(buf.Len()))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// maxFrameSize caps a single RPC message to protect the Sentry and
// Gofer from OOM if a malformed length header arrives (or a fuzzer
// sends one deliberately). 64 MB is vastly more than any real request.
const maxFrameSize = 64 * 1024 * 1024

// readFramed reads a single length-prefixed gob message into v.
func readFramed(r io.Reader, v interface{}) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return errFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewReader(buf)).Decode(v)
}

var errFrameTooLarge = &frameTooLargeError{}

type frameTooLargeError struct{}

func (e *frameTooLargeError) Error() string { return "gofer: frame exceeds maxFrameSize" }
