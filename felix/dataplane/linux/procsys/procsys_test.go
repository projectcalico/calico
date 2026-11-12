// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package procsys

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarding")
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Write(path, "1"); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1" {
		t.Errorf("file contains %q, want %q", got, "1")
	}
}

func TestWriteDoesNotCreateMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-iface")

	if err := Write(path, "1"); err == nil {
		t.Fatal("Write() to a missing file succeeded, want error")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Write() created %s", path)
	}
}

func TestConfigureInterface(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ipVersion int
		want      map[string]string
	}{
		{
			name:      "IPv4",
			ipVersion: 4,
			want: map[string]string{
				"/proc/sys/net/ipv4/conf/cali1/route_localnet": "1",
				"/proc/sys/net/ipv4/neigh/cali1/proxy_delay":   "0",
				"/proc/sys/net/ipv4/conf/cali1/proxy_arp":      "1",
				"/proc/sys/net/ipv4/conf/cali1/forwarding":     "1",
				"/proc/sys/net/ipv4/conf/cali1/rp_filter":      "2",
			},
		},
		{
			name:      "IPv6",
			ipVersion: 6,
			want: map[string]string{
				"/proc/sys/net/ipv6/conf/cali1/forwarding": "1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			err := ConfigureInterface("cali1", tc.ipVersion, "2", func(path, value string) error {
				got[path] = value
				return nil
			})
			if err != nil {
				t.Fatalf("ConfigureInterface() error = %v", err)
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("ConfigureInterface() wrote %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfigureInterfaceToleratesProxyDelayFailure(t *testing.T) {
	err := ConfigureInterface("cali1", 4, "1", func(path, value string) error {
		if path == "/proc/sys/net/ipv4/neigh/cali1/proxy_delay" {
			return errors.New("not supported")
		}
		return nil
	})
	if err != nil {
		t.Errorf("ConfigureInterface() error = %v, want nil", err)
	}
}

func TestConfigureInterfaceReturnsWriteError(t *testing.T) {
	writeErr := errors.New("boom")
	err := ConfigureInterface("cali1", 4, "1", func(path, value string) error {
		if path == "/proc/sys/net/ipv4/conf/cali1/proxy_arp" {
			return writeErr
		}
		return nil
	})
	if !errors.Is(err, writeErr) {
		t.Errorf("ConfigureInterface() error = %v, want %v", err, writeErr)
	}
}
