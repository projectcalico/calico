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

package typha

import (
	"strings"
	"testing"

	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

func TestKnownSyncerType(t *testing.T) {
	if !knownSyncerType(syncproto.SyncerTypeFelix) {
		t.Fatalf("expected felix to be a known syncer type")
	}
	if knownSyncerType("not-a-real-type") {
		t.Fatalf("expected unknown syncer type to be rejected")
	}
	// The error message lists the valid types, so it must mention a real one.
	if !strings.Contains(supportedSyncerTypes(), string(syncproto.SyncerTypeFelix)) {
		t.Fatalf("supported types list %q does not mention felix", supportedSyncerTypes())
	}
}

func TestValidateTLSFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   dumpFlags
		wantErr bool
	}{
		{
			name:  "unix socket ignores TLS flags",
			flags: dumpFlags{server: "", certFile: "c"}, // no --server: flags ignored
		},
		{
			name:  "plaintext TCP is allowed",
			flags: dumpFlags{server: "typha:5473"},
		},
		{
			name:  "full mutual TLS is allowed",
			flags: dumpFlags{server: "typha:5473", keyFile: "k", certFile: "c", caFile: "ca", serverCN: "typha-server"},
		},
		{
			name:    "partial TLS flags rejected",
			flags:   dumpFlags{server: "typha:5473", certFile: "c"}, // missing key/ca
			wantErr: true,
		},
		{
			name:    "missing server identity rejected",
			flags:   dumpFlags{server: "typha:5473", keyFile: "k", certFile: "c", caFile: "ca"}, // no CN/URI
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTLSFlags(tc.flags)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}
