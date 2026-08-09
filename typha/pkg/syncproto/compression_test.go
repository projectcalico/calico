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
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/gomega"
)

// TestCompressionRestartBoundaries verifies the contract that Compressor and
// Decompressor guarantee at a MsgDecoderRestart boundary: closing the old
// Compressor puts the whole old stream on the wire, and once the receiver
// has decoded the restart message it can discard its Decompressor and start
// a fresh one without losing or corrupting any bytes of the next stream.
//
// It models a connection's full lifecycle over a pipe, with the sender
// gated on the receiver's ACK at each boundary exactly like the sync
// protocol:
//
//	stream 0 (uncompressed handshake) -> restart
//	stream 1 (cached binary snapshot) -> embedded restart
//	stream 2 (per-connection delta stream, flushed mid-stream) -> EOF
func TestCompressionRestartBoundaries(t *testing.T) {
	for _, alg := range append([]CompressionAlgorithm{""}, AllCompressionAlgorithms...) {
		t.Run(string(alg), func(t *testing.T) {
			RegisterTestingT(t)

			pr, pw := io.Pipe()
			defer func() {
				_ = pr.Close()
				_ = pw.Close()
			}()

			// Buffered, and closed on exit, so that neither side can stay
			// blocked on the other if an assertion fails first.
			acks := make(chan struct{}, 2)
			defer close(acks)
			writerErr := make(chan error, 1)
			go func() {
				err := writeTestStreams(pw, alg, acks)
				if err != nil {
					// Unblock the reader so the failure surfaces there too.
					_ = pw.CloseWithError(err)
				}
				writerErr <- err
			}()

			// Stream 0: handshake phase, always uncompressed.
			hostnames, err := readTestStream("", pr, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(hostnames).To(Equal(expectedHostnames(0)))
			acks <- struct{}{}

			// Stream 1: snapshot with embedded restart at the end.
			hostnames, err = readTestStream(alg, pr, true)
			Expect(err).NotTo(HaveOccurred())
			Expect(hostnames).To(Equal(expectedHostnames(1)))
			acks <- struct{}{}

			// Stream 2: delta stream, runs until the sender closes the
			// connection.
			hostnames, err = readTestStream(alg, pr, false)
			Expect(err).To(MatchError(io.EOF))
			Expect(hostnames).To(Equal(expectedHostnames(2)))

			Expect(<-writerErr).NotTo(HaveOccurred())
		})
	}
}

const msgsPerStream = 3

func testHostname(stream, i int) string {
	return fmt.Sprintf("stream-%d-msg-%d", stream, i)
}

func expectedHostnames(stream int) []string {
	var hostnames []string
	for i := 0; i < msgsPerStream; i++ {
		hostnames = append(hostnames, testHostname(stream, i))
	}
	return hostnames
}

// writeTestStreams plays the sender's side: each stream ends with a flush,
// then the restart message, then Close on its Compressor -- the sequence
// that keeps the restart message in the stream's final block -- and the
// next stream starts only after the receiver ACKs.
func writeTestStreams(w *io.PipeWriter, alg CompressionAlgorithm, acks chan struct{}) error {
	writeMsgs := func(enc *gob.Encoder, stream int) error {
		for i := 0; i < msgsPerStream; i++ {
			err := enc.Encode(&Envelope{Message: MsgClientHello{
				Hostname: testHostname(stream, i),
				Info:     strings.Repeat("payload ", 100),
			}})
			if err != nil {
				return err
			}
		}
		return nil
	}
	restartMsg := &Envelope{Message: MsgDecoderRestart{
		Message:              "switch",
		CompressionAlgorithm: alg,
	}}
	endStream := func(c Compressor, enc *gob.Encoder) error {
		return CloseWithFinalMessage(c, func() error {
			return enc.Encode(restartMsg)
		})
	}

	// Stream 0: uncompressed handshake phase.
	c, err := NewStreamCompressor("", w)
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(c)
	if err := writeMsgs(enc, 0); err != nil {
		return err
	}
	if err := endStream(c, enc); err != nil {
		return err
	}
	<-acks

	// Stream 1: mimics the cached binary snapshot: pre-compressed into a
	// buffer with the snapshot compressor, then written to the connection
	// as raw bytes.
	var buf bytes.Buffer
	c, err = NewSnapshotCompressor(alg, &buf)
	if err != nil {
		return err
	}
	enc = gob.NewEncoder(c)
	if err := writeMsgs(enc, 1); err != nil {
		return err
	}
	if err := endStream(c, enc); err != nil {
		return err
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	<-acks

	// Stream 2: per-connection delta stream; messages are flushed as they
	// are written.
	c, err = NewStreamCompressor(alg, w)
	if err != nil {
		return err
	}
	enc = gob.NewEncoder(c)
	for i := 0; i < msgsPerStream; i++ {
		err := enc.Encode(&Envelope{Message: MsgClientHello{
			Hostname: testHostname(2, i),
			Info:     strings.Repeat("payload ", 100),
		}})
		if err != nil {
			return err
		}
		if err := c.Flush(); err != nil {
			return err
		}
	}
	if err := c.Close(); err != nil {
		return err
	}
	return w.Close()
}

// TestCompressionBlockAlignedBoundary pins the restart-boundary contract at
// stream sizes that are exact multiples of zstd's 128KiB block size.  At
// those sizes, closing a zstd stream with no pending data emits an *empty*
// final block whose bytes a synchronous decoder never consumes -- they would
// be stranded at the boundary and corrupt the next stream.  The sender-side
// discipline (flush, then write the stream's final message, then close)
// keeps the final block non-empty, which this test verifies byte-for-byte:
// stream A's decoded length is exact, and stream B decodes cleanly from the
// very next byte.
func TestCompressionBlockAlignedBoundary(t *testing.T) {
	const blockSize = 128 * 1024
	tail := []byte("final message of the stream")
	constructors := map[string]func(CompressionAlgorithm, io.Writer) (Compressor, error){
		"stream":   NewStreamCompressor,
		"snapshot": NewSnapshotCompressor,
	}
	// The dangerous sizes: the stream's data ends exactly on a block
	// boundary, either at the flush before the final message (bulk aligned)
	// or -- the case the flush exists to prevent -- at the end of the final
	// message itself (bulk+tail aligned).
	bulkLens := []int{
		blockSize - 1, blockSize, blockSize + 1, 2 * blockSize,
		blockSize - len(tail), 2*blockSize - len(tail),
	}
	for _, alg := range append([]CompressionAlgorithm{""}, AllCompressionAlgorithms...) {
		for name, newCompressor := range constructors {
			for _, bulkLen := range bulkLens {
				t.Run(fmt.Sprintf("%s/%s/%d", alg, name, bulkLen), func(t *testing.T) {
					RegisterTestingT(t)

					bulk := make([]byte, bulkLen)
					for i := range bulk {
						bulk[i] = byte(i)
					}

					// Stream A ends via CloseWithFinalMessage; stream B
					// follows it on the same "connection".
					var conn bytes.Buffer
					c, err := newCompressor(alg, &conn)
					Expect(err).NotTo(HaveOccurred())
					_, err = c.Write(bulk)
					Expect(err).NotTo(HaveOccurred())
					err = CloseWithFinalMessage(c, func() error {
						_, err := c.Write(tail)
						return err
					})
					Expect(err).To(Succeed())

					c, err = NewStreamCompressor(alg, &conn)
					Expect(err).NotTo(HaveOccurred())
					_, err = c.Write([]byte("next stream"))
					Expect(err).NotTo(HaveOccurred())
					Expect(c.Close()).To(Succeed())

					// Hide the buffer's type: zstd's Reset has a fast path
					// for in-memory readers that bypasses streaming decode.
					r := struct{ io.Reader }{&conn}
					d, err := NewDecompressor(alg, r)
					Expect(err).NotTo(HaveOccurred())
					got := make([]byte, len(bulk)+len(tail))
					_, err = io.ReadFull(d, got)
					Expect(err).NotTo(HaveOccurred())
					Expect(got[:len(bulk)]).To(Equal(bulk))
					Expect(got[len(bulk):]).To(Equal(tail))
					d.Close()

					d, err = NewDecompressor(alg, r)
					Expect(err).NotTo(HaveOccurred())
					next, err := io.ReadAll(d)
					Expect(err).NotTo(HaveOccurred())
					Expect(string(next)).To(Equal("next stream"))
					d.Close()
				})
			}
		}
	}
}

// TestCompressionUnknownAlgorithm verifies that every constructor rejects an
// algorithm it does not recognise instead of silently passing data through.
func TestCompressionUnknownAlgorithm(t *testing.T) {
	RegisterTestingT(t)

	var buf bytes.Buffer
	_, err := NewStreamCompressor("bogus", &buf)
	Expect(err).To(HaveOccurred())
	_, err = NewSnapshotCompressor("bogus", &buf)
	Expect(err).To(HaveOccurred())
	_, err = NewDecompressor("bogus", &buf)
	Expect(err).To(HaveOccurred())
}

// TestZstdDecoderWindowCap verifies that the decoder rejects zstd frames that
// declare a window larger than maxZstdWindowSize (bounding the memory a
// malicious peer can make us allocate), while accepting frames up to the cap.
func TestZstdDecoderWindowCap(t *testing.T) {
	// More than one block of compressible data, so the streaming encoder
	// must declare its configured window in the frame header rather than
	// falling back to a single-segment frame sized by the content.
	payload := bytes.Repeat([]byte("payload "), 32*1024)

	encode := func(windowSize int) *bytes.Buffer {
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf, zstd.WithWindowSize(windowSize))
		Expect(err).NotTo(HaveOccurred())
		_, err = zw.Write(payload)
		Expect(err).NotTo(HaveOccurred())
		Expect(zw.Close()).To(Succeed())
		return &buf
	}

	t.Run("accepts a window at the cap", func(t *testing.T) {
		RegisterTestingT(t)
		buf := encode(maxZstdWindowSize)
		d, err := NewDecompressor(CompressionZstd, struct{ io.Reader }{buf})
		Expect(err).NotTo(HaveOccurred())
		defer d.Close()
		got, err := io.ReadAll(d)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(payload))
	})

	t.Run("rejects a window above the cap", func(t *testing.T) {
		RegisterTestingT(t)
		buf := encode(2 * maxZstdWindowSize)
		d, err := NewDecompressor(CompressionZstd, struct{ io.Reader }{buf})
		Expect(err).NotTo(HaveOccurred())
		defer d.Close()
		_, err = io.ReadAll(d)
		Expect(err).To(MatchError(zstd.ErrWindowSizeExceeded))
	})
}

// readTestStream plays the receiver's side for one stream: a fresh
// Decompressor and gob decoder, reading until the restart message (or EOF)
// and returning the hostnames of the messages seen.  The returned error is
// the decode error that ended the stream, nil for a clean restart.
func readTestStream(alg CompressionAlgorithm, r io.Reader, expectRestart bool) ([]string, error) {
	d, err := NewDecompressor(alg, r)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	dec := gob.NewDecoder(d)
	var hostnames []string
	for {
		var envelope Envelope
		if err := dec.Decode(&envelope); err != nil {
			return hostnames, err
		}
		switch msg := envelope.Message.(type) {
		case MsgClientHello:
			hostnames = append(hostnames, msg.Hostname)
		case MsgDecoderRestart:
			if !expectRestart {
				return hostnames, fmt.Errorf("unexpected restart message")
			}
			return hostnames, nil
		default:
			return hostnames, fmt.Errorf("unexpected message: %#v", envelope.Message)
		}
	}
}
