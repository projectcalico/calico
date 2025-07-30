package fvtests_test

import (
	"context"
	"maps"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	fvtests "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
)

func TestReconnection(t *testing.T) {
	h, recorder, clientStoppedC := setUpReconnectionTest(t)

	// Deliberately configure the servers with different KVs.  When the client
	// flip-flops between the two, it should sync with whichever server it
	// connects to.  This may mean synthesising a deletion for the second key.
	h0ConfigUpdates := h[0].SendConfigUpdates(1)
	h[0].SendStatus(api.InSync)
	h1ConfigUpdates := h[1].SendConfigUpdates(2)
	h[1].SendStatus(api.InSync)

	t.Log("Waiting for client to connect to h[0]")
	waitForConnection(t, h[0].Server, clientStoppedC)
	t.Log("Client connected to h[0]")
	Eventually(recorder.KVs).Should(Equal(h0ConfigUpdates))

	// Push client off h[0], it should consistently connect to h[1]
	h[0].Server.TerminateRandomConnection(logrus.WithField("disconnection", 1), "test")
	waitForConnection(t, h[1].Server, clientStoppedC)

	// Keys that are common to both h[0] and h[1] get converted from "new" to "update".
	tweakUpdateTypes(h1ConfigUpdates, h0ConfigUpdates)
	Eventually(recorder.KVs).Should(Equal(h1ConfigUpdates))

	// And so on...
	h[1].Server.TerminateRandomConnection(logrus.WithField("disconnection", 2), "test")
	waitForConnection(t, h[0].Server, clientStoppedC)
	// Keys that are common to both h[0] and h[1] get converted from "new" to "update".
	tweakUpdateTypes(h0ConfigUpdates, h1ConfigUpdates)
	Eventually(recorder.KVs).Should(Equal(h0ConfigUpdates))
}

func TestReconnectionNewServerNotInSync(t *testing.T) {
	h, recorder, clientStoppedC := setUpReconnectionTest(t)

	// Deliberately configure the servers with different KVs.  When the client
	// flip-flops between the two, it should sync with whichever server it
	// connects to.  This may mean synthesising a deletion for the second key.
	h0ConfigUpdates := h[0].SendConfigUpdates(2)
	h[0].SendStatus(api.InSync)
	h1ConfigUpdates := h[1].SendConfigUpdates(1)
	// h[1] _not_ in sync yet.

	t.Log("Waiting for client to connect to h[0]")
	waitForConnection(t, h[0].Server, clientStoppedC)
	t.Log("Client connected to h[0]")
	Eventually(recorder.KVs).Should(Equal(h0ConfigUpdates))

	// Push client off h[0], it should consistently connect to h[1]
	h[0].Server.TerminateRandomConnection(logrus.WithField("disconnection", 1), "test")
	waitForConnection(t, h[1].Server, clientStoppedC)

	// Since h[1] is not in sync and h[0] has a key that's not present on h[1]
	// we expect the client to have the updated value from h[1] but to also
	// keep the extra value from h[0].
	tweakUpdateTypes(h1ConfigUpdates, h0ConfigUpdates)
	h0Withh1Overlay := maps.Clone(h0ConfigUpdates)
	for k, v := range h1ConfigUpdates {
		h0Withh1Overlay[k] = v
	}
	Eventually(recorder.KVs).Should(Equal(h0Withh1Overlay))
	Consistently(recorder.Status).Should(Equal(api.ResyncInProgress))

	// Reconnect to h[0], should get back to being in-sync.
	h[1].Server.TerminateRandomConnection(logrus.WithField("disconnection", 2), "test")
	waitForConnection(t, h[0].Server, clientStoppedC)
	// Keys that are common to both h[0] and h[1] get converted from "new" to "update".
	tweakUpdateTypes(h0ConfigUpdates, h0Withh1Overlay)
	Eventually(recorder.Status).Should(Equal(api.InSync))
	Eventually(recorder.KVs).Should(Equal(h0ConfigUpdates))

	// Push client off h[0], it should consistently connect to h[1]
	h[0].Server.TerminateRandomConnection(logrus.WithField("disconnection", 1), "test")
	waitForConnection(t, h[1].Server, clientStoppedC)
	tweakUpdateTypes(h0Withh1Overlay, h0ConfigUpdates)
	Eventually(recorder.KVs).Should(Equal(h0Withh1Overlay))

	// Now h[1] becomes in-sync, should clean up the old keys.
	h[1].SendStatus(api.InSync)
	Eventually(recorder.Status).Should(Equal(api.InSync))
	Eventually(recorder.KVs).Should(Equal(h1ConfigUpdates))
}

func tweakUpdateTypes(currentServerUpdates map[string]api.Update, prevServerUpdates map[string]api.Update) {
	for k, v := range currentServerUpdates {
		if _, ok := prevServerUpdates[k]; ok {
			v.UpdateType = api.UpdateTypeKVUpdated
			currentServerUpdates[k] = v
		}
	}
}

func setUpReconnectionTest(t *testing.T) (
	[2]*ServerHarness,
	*fvtests.StateRecorder,
	chan struct{},
) {
	RegisterTestingT(t)
	logutils.RedirectLogrusToTestingT(t)

	var h [2]*ServerHarness
	for i := 0; i < 2; i++ {
		h[i] = NewHarness()
		t.Cleanup(h[i].Stop)
		h[i].Start()
		t.Logf("h[%d] is running with address: %s", i, h[i].Addr())
	}

	// Set up a reconnection-aware client (by added a DedupeBuffer).
	recorder := fvtests.NewRecorder()
	deduper := dedupebuffer.New()
	client := syncclient.New(
		discovery.New(discovery.WithAddrsOverride([]string{
			h[0].Addr(),
			h[1].Addr(),
		})),
		"test-version",
		"test-host",
		"test-info",
		deduper,
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix},
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go deduper.SendToSinkForever(recorder)
	t.Cleanup(deduper.Stop)
	go recorder.Loop(ctx)

	err := client.Start(ctx)
	if err != nil {
		t.Fatal("Failed to start client:", err)
	}
	clientFinished := make(chan struct{})
	go func() {
		client.Finished.Wait()
		close(clientFinished)
	}()
	t.Cleanup(func() {
		t.Log("Shutting down at end of test...")
		cancel()
		select {
		case <-clientFinished:
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for client to finish")
		}
	})
	return h, recorder, clientFinished
}

func waitForConnection(t *testing.T, server *syncserver.Server, done chan struct{}) {
	t.Helper()
	timeout := time.After(time.Second)
	for server.NumActiveConnections() != 1 {
		select {
		case <-done:
			t.Fatal("Client failed")
		case <-timeout:
			t.Fatal("Client failed to connect within timeout")
		case <-time.After(10 * time.Millisecond):
			continue
		}
	}
}
