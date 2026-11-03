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
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLengthEndpoint covers the core packet-size contract: GET /length/{N}
// returns a body whose length, after TrimSpace, is exactly N.
func TestLengthEndpoint(t *testing.T) {
	for _, n := range []int{1, 10, 1400, 10000} {
		req := httptest.NewRequest(http.MethodGet, "/length/"+strconv.Itoa(n), nil)
		rec := httptest.NewRecorder()
		handleLength(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("N=%d: status = %d, want 200", n, rec.Code)
			continue
		}
		got := len(strings.TrimSpace(rec.Body.String()))
		if got != n {
			t.Errorf("N=%d: trimmed body length = %d, want %d", n, got, n)
		}
	}
}

func TestLengthZero(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/length/0", nil)
	rec := httptest.NewRecorder()
	handleLength(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body length = %d, want 0", rec.Body.Len())
	}
}

func TestLengthBadInput(t *testing.T) {
	for _, path := range []string{"/length/abc", "/length/-5", "/length/"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handleLength(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, rec.Code)
		}
	}
}

func TestPostReturnsByteCount(t *testing.T) {
	const length = 1234
	body := strings.Repeat("X", length)
	req := httptest.NewRequest(http.MethodPost, "/post", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handlePost(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got, err := strconv.Atoi(strings.TrimSpace(rec.Body.String()))
	if err != nil {
		t.Fatalf("could not parse response %q: %v", rec.Body.String(), err)
	}
	if got != length {
		t.Errorf("reported byte count = %d, want %d", got, length)
	}
}

func TestPostGetReturnsHelp(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/post", nil)
	rec := httptest.NewRecorder()
	handlePost(rec, req)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Errorf("GET /post: status=%d bodyLen=%d, want 200 with help text", rec.Code, rec.Body.Len())
	}
}

func TestRootAndNotFound(t *testing.T) {
	root := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handleRoot(rec, root)
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Errorf("GET /: status=%d bodyLen=%d, want 200 non-empty", rec.Code, rec.Body.Len())
	}

	other := httptest.NewRequest(http.MethodGet, "/nope", nil)
	rec = httptest.NewRecorder()
	handleRoot(rec, other)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope: status=%d, want 404", rec.Code)
	}
}

// TestUDPEcho verifies the UDP listener echoes a datagram back verbatim.
func TestUDPEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	go serveUDP(pc)

	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := strings.Repeat("0123456789", 100) // 1000 bytes, no whitespace
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload)+16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestDispatch checks the registry: client and server are registered and the
// default selection (empty MODE) resolves to client.
func TestDispatch(t *testing.T) {
	if _, ok := lookupMode("client"); !ok {
		t.Error("client mode not registered")
	}
	if _, ok := lookupMode("server"); !ok {
		t.Error("server mode not registered")
	}
	if _, ok := lookupMode(defaultMode); !ok {
		t.Errorf("default mode %q not registered", defaultMode)
	}
	if _, ok := lookupMode("nope"); ok {
		t.Error("unknown mode unexpectedly resolved")
	}
}

// TestResolveServerPort covers PORT env parsing: empty falls back to the
// default, valid ports pass through, and out-of-range / non-numeric values are
// rejected. This is the logic serverMode.Run relies on but never exercises in
// its own tests (it binds real sockets), so guard it directly.
func TestResolveServerPort(t *testing.T) {
	valid := []struct {
		in   string
		want int
	}{
		{"", defaultServerPort},
		{"1", 1},
		{"5000", 5000},
		{"65535", 65535},
	}
	for _, tc := range valid {
		got, err := resolveServerPort(tc.in)
		if err != nil {
			t.Errorf("resolveServerPort(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveServerPort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
	for _, in := range []string{"0", "-1", "65536", "70000", "abc", "5000x"} {
		if _, err := resolveServerPort(in); err == nil {
			t.Errorf("resolveServerPort(%q) = nil error, want error", in)
		}
	}
}

// TestResolveMode locks in the MODE dispatch contract the PR rests on: an empty
// MODE must resolve to the client mode (backward compatibility for callers that
// set no MODE, e.g. the maglev test), "server" selects the server mode, and an
// unknown value is reported as unresolved.
func TestResolveMode(t *testing.T) {
	if m, name, ok := resolveMode(""); !ok || name != defaultMode || m.Name() != defaultMode {
		t.Errorf("resolveMode(\"\") = (%v, %q, %v), want the %q mode", m, name, ok, defaultMode)
	}
	if m, name, ok := resolveMode("server"); !ok || name != "server" || m.Name() != "server" {
		t.Errorf("resolveMode(\"server\") = (%v, %q, %v), want the server mode", m, name, ok)
	}
	if _, name, ok := resolveMode("bogus"); ok {
		t.Errorf("resolveMode(%q) resolved unexpectedly", name)
	}
}

// TestClientModeRequiresURL locks in the Mode.Run error contract for client
// mode: a missing required -url returns an error (which main maps to a non-zero
// exit) rather than calling os.Exit — so the mode is composable and testable.
func TestClientModeRequiresURL(t *testing.T) {
	if err := (clientMode{}).Run([]string{}); err == nil {
		t.Error("clientMode.Run with no -url = nil error, want error")
	}
}
