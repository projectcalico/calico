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

package fvtests_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/snapshotdump"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
)

// TestUnixSocketDump checks that Typha serves the sync protocol on its private
// unix domain socket (no TLS) and that "calico typha client dump", dialing that
// socket via the unix:// scheme, recovers the served snapshot.  This is the
// in-pod diagnostics path used by "calicoctl cluster diags".
func TestUnixSocketDump(t *testing.T) {
	g := gomega.NewWithT(t)

	socketPath := filepath.Join(t.TempDir(), "typha.sock")

	// Minimal datastore -> cache -> server pipeline (mirrors the Ginkgo harness).
	decoupler := calc.NewSyncerCallbacksDecoupler()
	cache := snapcache.New(snapcache.Config{MaxBatchSize: 10, WakeUpInterval: 50 * time.Millisecond})
	valFilter := calc.NewValidationFilter(cache)

	// Cancelling the context tears the server down.  We don't block on
	// server.Finished here: this test is about the dump round-trip (which
	// completes below), not server shutdown ordering, and tearing the whole
	// server down mid-snapshot races with the shared snapshot goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go decoupler.SendToContext(ctx, valFilter)

	server := syncserver.New(
		map[syncproto.SyncerType]syncserver.BreadcrumbProvider{syncproto.SyncerTypeFelix: cache},
		syncserver.Config{
			Port:         syncserver.PortRandom,
			DropInterval: 50 * time.Millisecond,
			SocketPath:   socketPath,
		},
	)
	cache.Start(ctx)
	server.Start(ctx)

	// Seed a snapshot and mark it in-sync.
	decoupler.OnStatusUpdated(api.ResyncInProgress)
	decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
	decoupler.OnStatusUpdated(api.InSync)

	// Dump the felix snapshot over the unix socket.
	var out strings.Builder
	err := snapshotdump.Dump(ctx, snapshotdump.Config{
		Server:      "unix://" + socketPath,
		SyncerTypes: []syncproto.SyncerType{syncproto.SyncerTypeFelix},
		Format:      snapshotdump.FormatNDJSON,
		Out:         &out,
		IdleTimeout: 10 * time.Second,
		MyVersion:   "test",
		MyHostname:  "test-host",
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	dump := out.String()
	g.Expect(dump).To(gomega.ContainSubstring(`{"section":"felix","event":"begin"}`))
	g.Expect(dump).To(gomega.ContainSubstring(`/calico/v1/config/foobar`))
	g.Expect(dump).To(gomega.ContainSubstring(`bazzbiff`))
	// The end marker must report in-sync with the single seeded key.
	g.Expect(dump).To(gomega.MatchRegexp(`"section":"felix","event":"end","numKVs":1,"status":"in-sync"`))
}
