// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syncproto

import (
	"bufio"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

// The sync protocol switches the server-to-client encoding mid-connection:
// MsgDecoderRestart marks a hard boundary between an old stream and a new
// one.  Both sides rely on these invariants at every boundary:
//
//   - Sender: the restart message is the last data written to the old
//     Compressor, via CloseWithFinalMessage: flush, write the message, then
//     Close with no flush in between.  Close pushes every remaining byte --
//     including any stream terminator -- through to the connection, and the
//     sender sends nothing more until the client ACKs.  The next bytes on
//     the wire begin a brand-new stream from a brand-new Compressor.  The
//     flush-before-the-final-message step pins the message (much smaller
//     than a compression block) inside the stream's final block; without
//     it, a stream whose data ends exactly on a block boundary would end in
//     an *empty* final block, which zstd's synchronous decoder never
//     consumes -- those bytes would be stranded on the wire and corrupt the
//     next stream.
//   - Receiver: because the old stream was terminated right after the restart
//     message, decoding that message means the Decompressor has consumed
//     exactly the old stream's bytes from the connection.  The receiver
//     discards it and creates a fresh Decompressor for the new stream.
//
// The implementations returned by the constructors below guarantee the
// properties each side needs, for every algorithm (including "none").  The
// server and client must access compression only through these interfaces.

// zstd window sizes.  The decoder allocates a history buffer as large as the
// window declared in the incoming frame header, so the cap bounds the memory
// a peer can make us allocate; without it, the library accepts windows up to
// 512MiB.  The encoder sizes must never exceed the decoder cap, or a client
// would reject the server's frames.  The cap leaves 4x headroom so that a
// future server can grow its windows without breaking existing clients.
const (
	// streamZstdWindowSize is the window for per-connection delta streams.
	// Deltas are written in small, frequently-flushed batches, so a modest
	// window is plenty, and the server holds one per connection.
	streamZstdWindowSize = 1 << 20
	// snapshotZstdWindowSize is the window for cached binary snapshots,
	// which are compressed once and shared by many connections.
	snapshotZstdWindowSize = 4 << 20
	// maxZstdWindowSize is the largest window NewDecompressor accepts.
	maxZstdWindowSize = 16 << 20
)

// Compressor is a compressing (or pass-through) writer with synchronous
// flush and close semantics, suitable for the sender's side of a restart
// boundary.
type Compressor interface {
	io.Writer

	// Flush compresses all data accepted by Write so far and writes it
	// through to the underlying writer.  It does not end the compressed
	// stream.
	Flush() error

	// Close ends the compressed stream and writes it, including any stream
	// terminator, through to the underlying writer.  The Compressor must not
	// touch the underlying writer after Close returns.  To end a stream that
	// a Decompressor must consume exactly, close it via
	// CloseWithFinalMessage rather than calling Close directly.
	Close() error
}

// Decompressor is a decompressing (or pass-through) reader that is safe to
// discard at a restart boundary.  Implementations must be synchronous: Read
// consumes from the underlying reader only the bytes needed to produce the
// data it returns, with no read-ahead past the end of a compressed stream.
// In particular, the Read that returns the final bytes of a terminated
// stream also consumes the stream's terminator.
type Decompressor interface {
	io.Reader

	// Close releases the Decompressor's resources.  It does not read from
	// the underlying reader.
	Close()
}

// CloseWithFinalMessage ends a compressed stream with a final message: it
// flushes the Compressor, calls encodeMsg to write the message, then closes
// the Compressor.  This is the only safe way to end a stream that a
// Decompressor must consume exactly: the flush pins the message inside the
// stream's final block (see the package comment above).
func CloseWithFinalMessage(c Compressor, encodeMsg func() error) error {
	if err := c.Flush(); err != nil {
		return err
	}
	if err := encodeMsg(); err != nil {
		return err
	}
	return c.Close()
}

// NewStreamCompressor returns a Compressor that writes a stream of small,
// frequently flushed messages to w, buffering output so that each Flush
// costs at most one write to w.  Pass algorithm "" for a pass-through
// (uncompressed) stream.
func NewStreamCompressor(algorithm CompressionAlgorithm, w io.Writer) (Compressor, error) {
	bw := bufio.NewWriter(w)
	switch algorithm {
	case CompressionSnappy:
		return &streamCompressor{c: snappy.NewBufferedWriter(bw), bw: bw}, nil
	case CompressionZstd:
		// Bound per-connection resource usage: one encoder goroutine and a
		// small window.  The library defaults (GOMAXPROCS goroutines and an
		// 8MiB window per Writer) add up quickly when the server has many
		// connections.
		zw, err := zstd.NewWriter(bw,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(streamZstdWindowSize),
		)
		if err != nil {
			return nil, err
		}
		return &streamCompressor{c: zw, bw: bw}, nil
	case "":
		return nopCompressor{bw}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// NewSnapshotCompressor returns a Compressor for building a binary snapshot
// in an in-memory buffer.  Unlike NewStreamCompressor, it favours
// compression speed and ratio over per-connection memory bounds (snapshots
// are compressed once and shared by many connections), and it does not
// buffer output.  Pass algorithm "" for a pass-through (uncompressed)
// snapshot.
func NewSnapshotCompressor(algorithm CompressionAlgorithm, w io.Writer) (Compressor, error) {
	switch algorithm {
	case CompressionSnappy:
		return snappy.NewBufferedWriter(w), nil
	case CompressionZstd:
		// Pin the window size rather than relying on the level's default,
		// which could drift past maxZstdWindowSize on a library upgrade.
		return zstd.NewWriter(w,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithWindowSize(snapshotZstdWindowSize),
		)
	case "":
		return passthroughCompressor{w}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// NewDecompressor returns a Decompressor that reads an algorithm-compressed
// stream from r.  Pass algorithm "" for a pass-through (uncompressed)
// stream.
func NewDecompressor(algorithm CompressionAlgorithm, r io.Reader) (Decompressor, error) {
	switch algorithm {
	case CompressionSnappy:
		// snappy's reader is synchronous: it reads exactly one chunk at a
		// time, only when it needs one to satisfy a Read.
		return nopCloserDecompressor{snappy.NewReader(r)}, nil
	case CompressionZstd:
		// WithDecoderConcurrency(1) selects the synchronous decode path: no
		// background goroutine, blocks are read with exact-size reads, and a
		// frame's trailing checksum is consumed by the same Read call that
		// returns the frame's final bytes.  The default asynchronous mode
		// reads ahead and would steal bytes from the next stream at a
		// restart boundary.
		return zstd.NewReader(r,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxWindow(maxZstdWindowSize),
		)
	case "":
		return nopCloserDecompressor{r}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// streamCompressor pairs a compression writer with the buffered writer
// beneath it so that Flush and Close write through to the destination.
type streamCompressor struct {
	// c is the compression writer; it writes compressed bytes to bw, which
	// batches them into writes on the destination.
	c  Compressor
	bw *bufio.Writer
}

func (s *streamCompressor) Write(p []byte) (int, error) {
	return s.c.Write(p)
}

func (s *streamCompressor) Flush() error {
	if err := s.c.Flush(); err != nil {
		return err
	}
	return s.bw.Flush()
}

func (s *streamCompressor) Close() error {
	if err := s.c.Close(); err != nil {
		return err
	}
	return s.bw.Flush()
}

// nopCompressor is the pass-through Compressor used when no compression is
// negotiated.  Its "stream" has no terminator, so Close only flushes.
type nopCompressor struct {
	bw *bufio.Writer
}

func (n nopCompressor) Write(p []byte) (int, error) { return n.bw.Write(p) }
func (n nopCompressor) Flush() error                { return n.bw.Flush() }
func (n nopCompressor) Close() error                { return n.bw.Flush() }

// nopCloserDecompressor adapts a reader with no resources to release.
type nopCloserDecompressor struct {
	io.Reader
}

func (nopCloserDecompressor) Close() {}

// passthroughCompressor is the pass-through Compressor for uncompressed
// snapshots; it has no buffering and its stream has no terminator.
type passthroughCompressor struct {
	io.Writer
}

func (passthroughCompressor) Flush() error { return nil }
func (passthroughCompressor) Close() error { return nil }
