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

// Package compression negotiates response compression for the HTTP servers in
// this repository.
package compression

import (
	"compress/flate"
	"fmt"
	"io"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/zstd"
)

// compressibleTypes are the content types worth compressing: the JSON these
// servers return in bulk, its newline-delimited form for bulk and streaming
// bodies, and the CSV the dashboards export. Each repeats its field names on
// every record, so it shrinks by one to two orders of magnitude.
//
// text/event-stream is deliberately absent. A compressed event stream does
// still deliver per event, because every Flush reaches the client as a complete
// block, but an intermediary that buffers one would stall it. That trade
// belongs to whoever wants it rather than arriving as a side effect here.
var compressibleTypes = []string{
	"application/json",
	"application/x-ndjson",
	"text/csv",
}

// zstdWindowSize bounds a pooled encoder's memory. JSON gains almost nothing
// from a larger window.
const zstdWindowSize = 1 << 20

// NewResponseCompressor returns middleware that compresses a response when the
// client offers an encoding for it and the response declares a compressible
// content type. Encodings are preferred in the order zstd, gzip, deflate; a
// client that offers none of them, or asks for identity, gets the response
// unchanged, as does a response that already carries a Content-Encoding.
//
// A handler has to set its content type before writing its status, or net/http
// labels the response by sniffing the body and this middleware sees no type to
// match against.
//
// The plain func type keeps this package free of the rest of the library, so a
// server that only wants compression does not take on the request codec too.
func NewResponseCompressor() func(http.Handler) http.Handler {
	compressor := chimiddleware.NewCompressor(flate.DefaultCompression, compressibleTypes...)

	// NewCompressor already registered gzip and deflate. SetEncoder prepends, so
	// naming zstd here makes it the preferred encoding. chi pools encoders that
	// implement Reset(io.Writer), which zstd's does, so an encoder's window is
	// reused across responses rather than rebuilt per request.
	compressor.SetEncoder("zstd", newZstdEncoder)

	return compressor.Handler
}

// newZstdEncoder builds the encoder chi hands each compressible response.
//
// It panics rather than returning nil on error, even though chi's EncoderFunc
// documents nil as the failure signal: chi does not guard against a nil
// encoder, so nil would surface either as a lost pool (SetEncoder's type
// assertion for Reset(io.Writer) fails and zstd is registered unpooled) or as a
// nil writer panicking mid-response. The options are constants, so a failure
// means a broken build of this package, and SetEncoder calls this once eagerly:
// the panic lands at startup, not in front of a caller.
func newZstdEncoder(w io.Writer, _ int) io.Writer {
	zw, err := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(zstdWindowSize))
	if err != nil {
		panic(fmt.Sprintf("compression: zstd encoder options are invalid: %v", err))
	}
	return zw
}
