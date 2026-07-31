/*
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

func init() { registerMode(serverMode{}) }

const (
	// defaultServerPort matches the port the packet-size e2e test expects.
	defaultServerPort = 5000

	// udpReadBuffer is the UDP datagram read size. Test payloads are < MTU, so
	// they are never truncated; datagrams larger than this would be truncated by
	// the kernel (out of range for the test).
	udpReadBuffer = 65535

	// lengthAlphabet is the whitespace-free filler used for /length responses.
	// It MUST contain no whitespace: the packet-size test asserts
	// len(strings.TrimSpace(body)) == N, so any whitespace would shorten the
	// trimmed length and fail the check. Content is otherwise irrelevant.
	lengthAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

	postHelp = "This URL is meant for testing POSTs. It returns the number of bytes received."
)

// serverMode is the HTTP + UDP "dataplane server" used by the packet-size e2e
// test. It replaces the former Flask + socat image. See DESIGN.md for the
// endpoint contract.
type serverMode struct{}

func (serverMode) Name() string { return "server" }

// resolveServerPort maps the PORT env value to a listen port. An empty value
// selects defaultServerPort; a non-empty value must parse as a valid TCP/UDP
// port (1-65535), otherwise an error is returned.
func resolveServerPort(env string) (int, error) {
	if env == "" {
		return defaultServerPort, nil
	}
	p, err := strconv.Atoi(env)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid PORT %q", env)
	}
	return p, nil
}

func (serverMode) Run(args []string) error {
	// Server config comes from the PORT env var only. Stray args are tolerated
	// (ignored) for parity with the old runme.sh wrapper; the --port CLI override
	// it accepted is intentionally not replicated. Discard the FlagSet's output
	// so an unknown arg (e.g. the old --port) is ignored quietly rather than
	// printing a "flag provided but not defined" error + usage to stderr.
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	_ = fs.Parse(args)

	port, err := resolveServerPort(os.Getenv("PORT"))
	if err != nil {
		return err
	}
	addr := ":" + strconv.Itoa(port)

	// UDP echo on the same port. Bind the unspecified address so Linux serves
	// both IPv4 and v4-mapped IPv6 from one socket (matching the old host="::").
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("udp listen on %s: %w", addr, err)
	}
	go serveUDP(pc)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/length/", handleLength)
	mux.HandleFunc("/post", handlePost)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen on %s: %w", addr, err)
	}
	log.Printf("rapidclient server listening on %s (tcp+udp)", addr)
	return http.Serve(ln, mux)
}

// handleRoot serves a static string at "/" and 404s every other unmatched path
// (the "/" pattern is ServeMux's catch-all).
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, _ = io.WriteString(w, "rapidclient dataplane server")
}

// handleLength serves exactly N whitespace-free bytes at /length/{N}.
func handleLength(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/length/"))
	if err != nil || n < 0 {
		http.Error(w, "length must be a non-negative integer", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	// Set Content-Length explicitly and write the body in one call so the response
	// is never chunk-framed, regardless of N. (net/http only auto-sets
	// Content-Length when the whole body fits its internal buffer (~2KB) before the
	// handler returns; larger bodies would otherwise fall back to chunked.) Keeping
	// the framing deterministic matches the contract DESIGN.md describes.
	body := lengthBody(n)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

// lengthBody returns n bytes drawn from lengthAlphabet (whitespace-free).
func lengthBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = lengthAlphabet[i%len(lengthAlphabet)]
	}
	return b
}

// handlePost returns the number of bytes in a POST body; any other method gets
// the help string (parity with the former Flask handler, which accepted GET).
func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		_, _ = io.WriteString(w, postHelp)
		return
	}
	// Count without buffering the (up to ~10000-byte) body.
	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = io.WriteString(w, strconv.FormatInt(n, 10))
}

// serveUDP echoes each received datagram back to its sender, verbatim.
//
// This is a single read→write loop, which is correct for any number of peers:
// each datagram is echoed to its own source addr, and the shared buf is safe to
// reuse precisely because one goroutine reads and writes it sequentially.
//
// CAVEAT — if you ever parallelise the UDP echo (e.g. to keep up with a
// concurrent packet-size test that fires probes in parallel rather than
// serially), you MUST copy buf[:n] before handing it to a goroutine, or the next
// ReadFrom will overwrite it mid-flight (data race / corrupted echo):
//
//	n, addr, _ := pc.ReadFrom(buf)
//	d := append([]byte(nil), buf[:n]...) // copy first
//	go pc.WriteTo(d, addr)
//
// You'd also want pc.(*net.UDPConn).SetReadBuffer(...) so bursts don't overflow
// SO_RCVBUF and silently drop datagrams. Neither is needed today: the test
// sends serially and wraps the UDP check in Eventually(), which retries any
// transient loss. See DESIGN.md ("UDP echo").
func serveUDP(pc net.PacketConn) {
	buf := make([]byte, udpReadBuffer)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			// A closed conn is terminal — returning avoids a hot spin loop
			// (and lets the test's deferred Close stop this goroutine).
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("udp read error: %v", err)
			continue
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil {
			log.Printf("udp write error: %v", err)
		}
	}
}
