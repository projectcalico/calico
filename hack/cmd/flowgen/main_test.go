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

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectcalico/calico/app-policy/policyscale"
)

func TestParseTargets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "targets")
	if err := os.WriteFile(file, []byte("# target pods\n10.0.0.1\n10.0.0.2, 10.0.0.3 # last\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, override, list string
		want                 []string
		wantErr              bool
	}{
		{name: "none"},
		{name: "override", override: "10.0.0.9", want: []string{"10.0.0.9"}},
		{name: "list", list: "10.0.0.1,10.0.0.2", want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "file", list: "@" + file, want: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{name: "both", override: "10.0.0.9", list: "10.0.0.1", wantErr: true},
		{name: "bad address", list: "10.0.0.1,nope", wantErr: true},
		{name: "empty list", list: ",", wantErr: true},
		{name: "missing file", list: "@" + file + ".missing", wantErr: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseTargets(c.override, c.list)
			if (err != nil) != c.wantErr {
				t.Fatalf("error %v, want error %v", err, c.wantErr)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if !got[i].Equal(net.ParseIP(c.want[i])) {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestDestinationRoundRobin(t *testing.T) {
	f := policyscale.NewFlow("192.0.2.10", 40000, "198.51.100.7", 443)
	if got := destination(nil)(f); got != "198.51.100.7:443" {
		t.Fatalf("without targets the generated destination is used, got %s", got)
	}
	dst := destination([]net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")})
	var got []string
	for range 4 {
		got = append(got, dst(f))
	}
	want := []string{"10.0.0.1:443", "10.0.0.2:443", "10.0.0.3:443", "10.0.0.1:443"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("9000, 80,8000-8002")
	want := []int{9000, 80, 8000, 8001, 8002}
	if err != nil || len(got) != len(want) {
		t.Fatalf("got %v %v, want %v", got, err, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"", "x", "0", "65536", "10-5", "1-x"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// Hold mode against listen mode on loopback: every connection opens, stays open, and is written
// to every interval, which is what keeps it alive in conntrack.
func TestHoldAgainstListen(t *testing.T) {
	listeners, err := listen("127.0.0.1", []int{0})
	if err != nil {
		t.Fatal(err)
	}
	port := listeners[0].Addr().(*net.TCPAddr).Port
	listened := make(chan listenResult, 1)
	go func() { listened <- serveListeners(listeners, 3*time.Second, nil, io.Discard) }()

	fx := policyscale.Build(policyscale.EgressAllowList())
	const (
		n        = 50
		interval = 100 * time.Millisecond
		duration = time.Second
	)
	payload := []byte("hold")
	res := runHold(fx.NewSampler(1, policyscale.FlowModel{Direction: policyscale.Egress}).Next, holdConfig{
		connections: n,
		rate:        1000,
		duration:    duration,
		dialTimeout: time.Second,
		interval:    interval,
		payload:     payload,
		port:        port,
		shards:      4,
		targets:     []net.IP{net.ParseIP("127.0.0.1")},
	}, nil, io.Discard)
	if res.opened != n || res.openAtEnd != n || res.failed != 0 || res.closed != 0 {
		t.Fatalf("hold: %+v", res)
	}
	lr := <-listened
	if lr.accepted != n {
		t.Fatalf("listen: %+v", lr)
	}
	// Each connection was open for most of the second, so it was written to several times.
	if min := uint64(n * len(payload) * 3); lr.bytes < min {
		t.Fatalf("the sink read %d bytes, want at least %d from %d connections written every %s", lr.bytes, min, n, interval)
	}
}
