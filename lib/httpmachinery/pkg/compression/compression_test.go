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

package compression_test

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/compression"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
)

// body is large and repetitive, the way a page of flows is: compression only
// kicks in past chi's minimum size, and the repetition is what makes the ratio
// worth having.
var body = `{"items":[` + strings.Repeat(`{"source_name":"client","dest_name":"server","protocol":"tcp"},`, 500) + `{}]}`

// serve runs the middleware over a handler that writes body with contentType,
// and returns the recorded response.
func serve(t *testing.T, acceptEncoding, contentType string) *http.Response {
	t.Helper()

	handler := compression.NewResponseCompressor()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set(header.ContentType, contentType)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))

	r := httptest.NewRequest(http.MethodGet, "/flows", nil)
	if acceptEncoding != "" {
		r.Header.Set("Accept-Encoding", acceptEncoding)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Result()
}

func TestNegotiatesEncoding(t *testing.T) {
	RegisterTestingT(t)

	for _, tc := range []struct {
		name           string
		acceptEncoding string
		expected       string
	}{
		// zstd is preferred over the gzip and deflate chi registers itself.
		{"chrome offers everything", "gzip, deflate, br, zstd", "zstd"},
		{"zstd only", "zstd", "zstd"},
		{"older browser, gzip only", "gzip, deflate", "gzip"},
		{"deflate only", "deflate", "deflate"},
		// Nothing we serve: the response goes out unchanged rather than in an
		// encoding the client did not ask for.
		{"brotli only, which we do not serve", "br", ""},
		{"identity", "identity", ""},
		{"no header at all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			rsp := serve(t, tc.acceptEncoding, header.ApplicationJSON)
			Expect(rsp.Header.Get("Content-Encoding")).To(Equal(tc.expected))
		})
	}
}

func TestCompressesOnlyCompressibleTypes(t *testing.T) {
	RegisterTestingT(t)

	for _, tc := range []struct {
		name        string
		contentType string
		compressed  bool
	}{
		{"json", header.ApplicationJSON, true},
		// The charset parameter must not defeat the match.
		{"json without charset", "application/json", true},
		{"ndjson", "application/x-ndjson", true},
		{"csv", "text/csv", true},
		{"csv with charset", "text/csv; charset=utf-8", true},
		// An event stream is left alone: an intermediary that buffered a
		// compressed one would stall it.
		{"event stream", header.TextEventStream, false},
		{"plain text", "text/plain; charset=utf-8", false},
		// Without the fix that sets the content type before the status, this is
		// what a JSON handler looks like to the compressor.
		{"no content type declared", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			rsp := serve(t, "zstd, gzip", tc.contentType)
			if tc.compressed {
				Expect(rsp.Header.Get("Content-Encoding")).NotTo(BeEmpty())
			} else {
				Expect(rsp.Header.Get("Content-Encoding")).To(BeEmpty())
			}
		})
	}
}

func TestRoundTripsTheBody(t *testing.T) {
	RegisterTestingT(t)

	t.Run("zstd", func(t *testing.T) {
		RegisterTestingT(t)
		rsp := serve(t, "zstd", header.ApplicationJSON)
		Expect(rsp.Header.Get("Content-Encoding")).To(Equal("zstd"))

		raw, err := io.ReadAll(rsp.Body)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(raw)).To(BeNumerically("<", len(body)/10), "repetitive JSON should shrink by more than 10x")

		zr, err := zstd.NewReader(strings.NewReader(string(raw)))
		Expect(err).NotTo(HaveOccurred())
		defer zr.Close()
		decoded, err := io.ReadAll(zr)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decoded)).To(Equal(body))
	})

	t.Run("gzip", func(t *testing.T) {
		RegisterTestingT(t)
		rsp := serve(t, "gzip", header.ApplicationJSON)
		Expect(rsp.Header.Get("Content-Encoding")).To(Equal("gzip"))

		gr, err := gzip.NewReader(rsp.Body)
		Expect(err).NotTo(HaveOccurred())
		defer gr.Close()
		decoded, err := io.ReadAll(gr)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decoded)).To(Equal(body))
	})
}

// A stale Content-Length would describe the uncompressed body and truncate the
// response at the client.
func TestDropsContentLengthWhenCompressing(t *testing.T) {
	RegisterTestingT(t)

	handler := compression.NewResponseCompressor()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		w.Header().Set("Content-Length", "9999")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))

	r := httptest.NewRequest(http.MethodGet, "/flows", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	rsp := w.Result()
	Expect(rsp.Header.Get("Content-Encoding")).To(Equal("zstd"))
	Expect(rsp.Header.Get("Content-Length")).To(BeEmpty())
}

// A handler that encoded its own body owns the encoding; double-compressing it
// would corrupt it.
func TestLeavesAnAlreadyEncodedResponseAlone(t *testing.T) {
	RegisterTestingT(t)

	handler := compression.NewResponseCompressor()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(header.ContentType, header.ApplicationJSON)
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}))

	r := httptest.NewRequest(http.MethodGet, "/flows", nil)
	r.Header.Set("Accept-Encoding", "zstd")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	rsp := w.Result()
	Expect(rsp.Header.Get("Content-Encoding")).To(Equal("gzip"))
	raw, err := io.ReadAll(rsp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(raw)).To(Equal(body), "the body must pass through untouched")
}

// A stream is only useful if each event reaches the client as the handler
// flushes it, rather than sitting in the encoder until the response ends. The
// handler here writes one event, waits until the client has read it, then
// writes a second; a swallowed flush would block the first read forever.
func TestStreamsEachFlush(t *testing.T) {
	RegisterTestingT(t)

	for _, tc := range []struct {
		name           string
		acceptEncoding string
		contentType    string
		open           func(io.Reader) (io.ReadCloser, error)
	}{
		{"zstd json", "zstd", "application/json", openZstd},
		{"gzip json", "gzip", "application/json", func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }},
		{"zstd ndjson", "zstd", "application/x-ndjson", openZstd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)

			read := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(header.ContentType, tc.contentType)
				for i := 1; i <= 2; i++ {
					_, _ = fmt.Fprintf(w, `{"event":%d}`+"\n", i)
					w.(http.Flusher).Flush()
					if i == 1 {
						select {
						case <-read:
						case <-r.Context().Done():
							return
						}
					}
				}
			})
			server := httptest.NewServer(compression.NewResponseCompressor()(handler))
			defer server.Close()

			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Accept-Encoding", tc.acceptEncoding)
			rsp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
			Expect(err).NotTo(HaveOccurred())
			defer rsp.Body.Close()
			Expect(rsp.Header.Get("Content-Encoding")).To(Equal(tc.acceptEncoding))

			decoded, err := tc.open(rsp.Body)
			Expect(err).NotTo(HaveOccurred())
			defer decoded.Close()

			// The first event must arrive before the handler is released to
			// write the second.
			first := make([]byte, len(`{"event":1}`)+1)
			_, err = io.ReadFull(decoded, first)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(first)).To(Equal(`{"event":1}` + "\n"))
			close(read)

			rest, err := io.ReadAll(decoded)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(rest)).To(Equal(`{"event":2}` + "\n"))
		})
	}
}

// openZstd adapts a zstd decoder to the ReadCloser the streaming test wants.
func openZstd(r io.Reader) (io.ReadCloser, error) {
	zr, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	return zr.IOReadCloser(), nil
}
