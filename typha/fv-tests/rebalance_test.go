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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	fvtests "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

// TestRebalanceToPreferredTypha checks that a client which ends up connected to
// a non-preferred Typha (because its preferred one was unavailable at connect
// time) later migrates onto the preferred Typha when the rebalance timer fires,
// and that it tells the server why it is leaving.
func TestRebalanceToPreferredTypha(t *testing.T) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	// Capture the server-side "client disconnected deliberately" log lines so we
	// can assert the goodbye (and its reason) reached the server.
	capture := &goodbyeLogCapture{}
	log.AddHook(capture)

	// The preferred endpoint is the first in the override list.  Reserve its
	// port now but don't start the server yet, so that the client is forced to
	// connect to the non-preferred endpoint first.
	preferredAddr := fmt.Sprintf("127.0.0.1:%d", reservePort(t))
	preferred := NewHarness()
	preferred.Config.Port = portFromAddr(t, preferredAddr)

	nonPreferred := NewHarness()
	nonPreferred.Start()
	t.Cleanup(nonPreferred.Stop)

	// Restart-aware client (it has a DedupeBuffer) so that rebalancing is
	// enabled.  Short rebalance interval so the test doesn't have to wait.
	recorder := fvtests.NewRecorder()
	deduper := dedupebuffer.New()
	client := syncclient.New(
		discovery.New("test-node", discovery.WithAddrsOverride([]string{preferredAddr, nonPreferred.Addr()})),
		"test-version",
		"test-host",
		"test-info",
		deduper,
		&syncclient.Options{
			SyncerType:        syncproto.SyncerTypeFelix,
			RebalanceInterval: 250 * time.Millisecond,
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go deduper.SendToSinkForever(recorder)
	t.Cleanup(deduper.Stop)
	go recorder.Loop(ctx)

	Expect(client.Start(ctx)).To(Succeed())
	clientFinished := make(chan struct{})
	go func() {
		client.Finished.Wait()
		close(clientFinished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-clientFinished:
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for client to finish")
		}
	})

	// The preferred endpoint is down, so the client connects to the
	// non-preferred one.
	Eventually(nonPreferred.Server.NumActiveConnections, "5s", "20ms").Should(Equal(1),
		"client should connect to the non-preferred Typha while the preferred one is down")

	// Bring up the preferred endpoint.  Register its cleanup only now that it's
	// started (Stop() dereferences the server).
	preferred.Start()
	t.Cleanup(preferred.Stop)
	Expect(preferred.Addr()).To(Equal(preferredAddr), "preferred server should bind the reserved port")

	// The rebalance timer should move the client onto the preferred Typha and
	// off the non-preferred one.
	Eventually(preferred.Server.NumActiveConnections, "10s", "20ms").Should(Equal(1),
		"client should rebalance onto the preferred Typha once it is available")
	Eventually(nonPreferred.Server.NumActiveConnections, "10s", "20ms").Should(Equal(0),
		"client should disconnect from the non-preferred Typha after rebalancing")

	// The client told the server why it disconnected, and the server logged it.
	Eventually(capture.Reasons, "5s", "20ms").Should(
		ContainElement("rebalancing to preferred Typha instance"),
		"server should log the goodbye reason sent by the client")

	// Once on its preferred Typha, the client should stay put (no churn).
	Consistently(preferred.Server.NumActiveConnections, "1s", "50ms").Should(Equal(1),
		"client should remain connected to its preferred Typha")
}

// reservePort grabs a free TCP port and immediately releases it, returning the
// port number.  Used to pre-allocate an address for a server we start later, so
// the client can be told to prefer an endpoint that is initially down.
func reservePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to reserve a port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("Failed to release reserved port: %v", err)
	}
	return port
}

func portFromAddr(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	Expect(err).NotTo(HaveOccurred())
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	Expect(err).NotTo(HaveOccurred())
	return port
}

// goodbyeLogCapture is a logrus hook that records the reasons from the server's
// "client disconnected deliberately" log lines, so a test can assert that the
// goodbye message reached the server with the expected reason.
type goodbyeLogCapture struct {
	mu      sync.Mutex
	reasons []string
}

func (c *goodbyeLogCapture) Levels() []log.Level { return log.AllLevels }

func (c *goodbyeLogCapture) Fire(e *log.Entry) error {
	if e.Message != "Client disconnected deliberately." {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := e.Data["reason"].(string); ok {
		c.reasons = append(c.reasons, r)
	}
	return nil
}

func (c *goodbyeLogCapture) Reasons() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.reasons...)
}
