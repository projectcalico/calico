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
	"errors"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

// ErrCompressorClosed is returned by Write and Flush on a closed
// Compressor.
var ErrCompressorClosed = errors.New("compressor is closed")

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

// Compressor is a compressing (or pass-through) writer that a sender can end
// at an exact point in its output, so that a receiver reading the other end
// stops at the same point.  The sync protocol needs that because it switches
// the server-to-client encoding mid-connection: MsgDecoderRestart is the last
// message of the old stream, and the bytes straight after it on the wire
// belong to a new stream with a new encoding.
type Compressor interface {
	io.Writer

	// Flush compresses everything written so far and writes it through to
	// the underlying writer.  The stream stays open.
	Flush() error

	// Close ends the stream: it writes everything written so far through to
	// the underlying writer, then releases the Compressor's resources.
	// Afterwards:
	//
	//   - a Decompressor on the other end can read every byte written to
	//     the Compressor, and consumes exactly the bytes the Compressor
	//     produced -- no more;
	//   - the Compressor rejects further writes and can be discarded;
	//   - the underlying writer is free for whatever comes next, including
	//     a stream from a different Compressor.
	//
	// A receiver that reads on past the end of the stream, instead of
	// stopping on the last message, may get a truncated-stream error rather
	// than a clean EOF.  The sync protocol never does: the last message of
	// a stream tells the receiver the stream has ended.
	//
	// Close is idempotent, so a teardown path can close a Compressor that
	// the protocol has already ended.
	Close() error
}

// Decompressor is a decompressing (or pass-through) reader that is safe to
// discard once it has returned the last data its Compressor wrote.
// Implementations are synchronous: a Read consumes from the underlying
// reader only the bytes needed to produce the data that Read returns, and
// never reads past the end of the data the Compressor wrote before its
// Close.
type Decompressor interface {
	io.Reader

	// Close releases the Decompressor's resources.  It does not read from
	// the underlying reader.
	Close()
}

// NewStreamCompressor returns a Compressor that writes a stream of small,
// frequently flushed messages to w, buffering output so that each Flush
// costs at most one write to w.
func NewStreamCompressor(algorithm CompressionAlgorithm, w io.Writer) (Compressor, error) {
	// The buffered writer batches the compressor's output; Flush and Close
	// push it through to w.
	bw := bufio.NewWriter(w)
	switch algorithm {
	case CompressionSnappy:
		return &snappyCompressor{w: snappy.NewBufferedWriter(bw), bw: bw}, nil
	case CompressionZstd:
		// Bound per-connection resource usage: one encoder goroutine and a
		// small window.  The library defaults (GOMAXPROCS goroutines and an
		// 8MiB window per Writer) add up quickly when the server has many
		// connections.
		zw, err := zstd.NewWriter(bw,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(streamZstdWindowSize),
			zstd.WithEncoderCRC(false),
		)
		if err != nil {
			return nil, err
		}
		return &zstdCompressor{w: zw, bw: bw}, nil
	case CompressionNone:
		return &nopCompressor{w: bw, bw: bw}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// NewSnapshotCompressor returns a Compressor for building a binary snapshot
// in an in-memory buffer.  Unlike NewStreamCompressor, it favours
// compression speed and ratio over per-connection memory bounds (snapshots
// are compressed once and shared by many connections), and it does not
// buffer output.
func NewSnapshotCompressor(algorithm CompressionAlgorithm, w io.Writer) (Compressor, error) {
	switch algorithm {
	case CompressionSnappy:
		return &snappyCompressor{w: snappy.NewBufferedWriter(w)}, nil
	case CompressionZstd:
		// Pin the window size rather than relying on the level's default,
		// which could drift past maxZstdWindowSize on a library upgrade.
		zw, err := zstd.NewWriter(w,
			zstd.WithEncoderLevel(zstd.SpeedFastest),
			zstd.WithWindowSize(snapshotZstdWindowSize),
			zstd.WithEncoderCRC(false),
		)
		if err != nil {
			return nil, err
		}
		return &zstdCompressor{w: zw}, nil
	case CompressionNone:
		return &nopCompressor{w: w}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// NewDecompressor returns a Decompressor that reads an algorithm-compressed
// stream from r.
func NewDecompressor(algorithm CompressionAlgorithm, r io.Reader) (Decompressor, error) {
	switch algorithm {
	case CompressionSnappy:
		// snappy's reader is synchronous: it reads exactly one chunk at a
		// time, only when it needs one to satisfy a Read.
		return nopCloserDecompressor{snappy.NewReader(r)}, nil
	case CompressionZstd:
		// WithDecoderConcurrency(1) selects the synchronous decode path.  It
		// reads blocks with exact-size reads, and once a Read has any data
		// to return it stops rather than fetching the next block, so it
		// never reads past the block the Compressor's Close ended on.  The
		// default asynchronous mode reads ahead and would steal bytes from
		// the next stream.
		return zstd.NewReader(r,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxWindow(maxZstdWindowSize),
		)
	case CompressionNone:
		return nopCloserDecompressor{r}, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm: %q", algorithm)
	}
}

// snappyCompressor writes a snappy stream.  A snappy stream has no
// terminator, so ending one is just a flush.
type snappyCompressor struct {
	w *snappy.Writer
	// bw is the buffered writer between w and the destination, or nil if
	// the destination is written directly.
	bw *bufio.Writer
}

func (c *snappyCompressor) Write(p []byte) (int, error) {
	if c.w == nil {
		return 0, ErrCompressorClosed
	}
	return c.w.Write(p)
}

func (c *snappyCompressor) Flush() error {
	if c.w == nil {
		return ErrCompressorClosed
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	return flushBuffer(c.bw)
}

func (c *snappyCompressor) Close() error {
	if c.w == nil {
		return nil
	}
	err := c.w.Close()
	c.w = nil
	if err != nil {
		return err
	}
	return flushBuffer(c.bw)
}

// zstdCompressor writes a zstd stream.
type zstdCompressor struct {
	w *zstd.Encoder
	// bw is the buffered writer between w and the destination, or nil if
	// the destination is written directly.
	bw *bufio.Writer
}

func (c *zstdCompressor) Write(p []byte) (int, error) {
	if c.w == nil {
		return 0, ErrCompressorClosed
	}
	return c.w.Write(p)
}

func (c *zstdCompressor) Flush() error {
	if c.w == nil {
		return ErrCompressorClosed
	}
	if err := c.w.Flush(); err != nil {
		return err
	}
	return flushBuffer(c.bw)
}

// Close flushes the frame's data and abandons the frame without terminating
// it, which is what keeps the boundary exactly at the last byte written.
//
// A zstd frame ends with a block carrying the last-block flag, and the
// encoder emits that block only from its own Close.  When everything written
// has already been flushed, the block is empty.  The synchronous decoder
// skips empty blocks -- it loops until a block yields data -- so it would
// read straight on into whatever follows the frame, which at a restart
// boundary is the next stream.  Flushing and dropping the encoder avoids
// that: the last thing on the wire is a block that carries data, and the
// decoder stops as soon as it has returned it.
//
// The unterminated frame costs the stream its trailing checksum, which is
// why the encoders are built with WithEncoderCRC(false): a checksum that is
// never written would only make both sides hash every block for nothing.
// No decoder outside this connection ever sees the frame, the connection is
// already integrity-checked by TLS or TCP, and the restart protocol stops
// the peer reading further: it discards this stream's Decompressor as soon
// as it decodes the final message.
func (c *zstdCompressor) Close() error {
	if c.w == nil {
		return nil
	}
	err := c.w.Flush()
	// Reset(nil) releases the encoder's buffers and detaches it from the
	// writer.  Flush has already waited for the encoder's goroutines, so
	// there is nothing left in flight.
	c.w.Reset(nil)
	c.w = nil
	if err != nil {
		return err
	}
	return flushBuffer(c.bw)
}

// nopCompressor is the pass-through Compressor used when no compression is
// negotiated.  Its "stream" is the plain bytes, so Flush and Close only have
// to push the buffered writer through.
type nopCompressor struct {
	w io.Writer
	// bw is the buffered writer, or nil if the destination is written
	// directly.  When set, it is also w.
	bw *bufio.Writer
}

func (c *nopCompressor) Write(p []byte) (int, error) {
	if c.w == nil {
		return 0, ErrCompressorClosed
	}
	return c.w.Write(p)
}

func (c *nopCompressor) Flush() error {
	if c.w == nil {
		return ErrCompressorClosed
	}
	return flushBuffer(c.bw)
}

func (c *nopCompressor) Close() error {
	if c.w == nil {
		return nil
	}
	err := flushBuffer(c.bw)
	c.w = nil
	return err
}

func flushBuffer(bw *bufio.Writer) error {
	if bw == nil {
		return nil
	}
	return bw.Flush()
}

// nopCloserDecompressor adapts a reader with no resources to release.
type nopCloserDecompressor struct {
	io.Reader
}

func (nopCloserDecompressor) Close() {}
