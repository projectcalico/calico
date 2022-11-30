// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package fvtests_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	. "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
)

// ServerHarness runs a syncserver.Server with a couple of cache syncer cache types and allows for creating test
// clients.  The server configuration can be adjusted after creation but before calling Start(). Stop() should be
// called in an AfterEach.  The server runs on a random high numbered port.
type ServerHarness struct {
	Decoupler, BGPDecoupler *calc.SyncerCallbacksDecoupler
	ValFilter               *calc.ValidationFilter
	cacheCxt                context.Context
	cacheCancel             context.CancelFunc
	FelixCache, BGPCache    *snapcache.Cache
	Server                  *syncserver.Server
	serverCxt               context.Context
	ServerCancel            context.CancelFunc
	Config                  syncserver.Config

	ClientStates     []*ClientState
	NoOpClientStates []*ClientState

	updIdx int
}

func NewHarness() *ServerHarness {
	// Set up a pipeline:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	h := &ServerHarness{}
	h.Decoupler = calc.NewSyncerCallbacksDecoupler()
	h.FelixCache = snapcache.New(snapcache.Config{
		// Set the batch size small, so we can force new Breadcrumbs easily.
		MaxBatchSize: 10,
		// Reduce the wake-up interval from the default to give us faster tear down.
		WakeUpInterval: 50 * time.Millisecond,
	})
	h.BGPDecoupler = calc.NewSyncerCallbacksDecoupler()
	h.BGPCache = snapcache.New(snapcache.Config{
		// Set the batch size small, so we can force new Breadcrumbs easily.
		MaxBatchSize: 10,
		// Reduce the wake-up interval from the default to give us faster tear down.
		WakeUpInterval: 50 * time.Millisecond,
	})
	h.cacheCxt, h.cacheCancel = context.WithCancel(context.Background())
	h.ValFilter = calc.NewValidationFilter(h.FelixCache)
	h.Config = syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         syncserver.PortRandom,
		DropInterval: 50 * time.Millisecond,
	}
	return h
}

type ClientState struct {
	clientCxt    context.Context
	clientCancel context.CancelFunc
	client       *syncclient.SyncerClient
	recorder     *StateRecorder
	syncerType   syncproto.SyncerType
}

func (h *ServerHarness) Start() {
	h.Server = syncserver.New(
		map[syncproto.SyncerType]syncserver.BreadcrumbProvider{
			syncproto.SyncerTypeFelix: h.FelixCache,
			syncproto.SyncerTypeBGP:   h.BGPCache,
		},
		h.Config)

	go h.Decoupler.SendToContext(h.cacheCxt, h.ValFilter)
	go h.BGPDecoupler.SendToContext(h.cacheCxt, h.BGPCache)
	h.FelixCache.Start(h.cacheCxt)
	h.BGPCache.Start(h.cacheCxt)
	h.serverCxt, h.ServerCancel = context.WithCancel(context.Background())
	h.Server.Start(h.serverCxt)
}

func (h *ServerHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", h.Server.Port())
}

func (h *ServerHarness) Stop() {
	allClients := append(h.ClientStates, h.NoOpClientStates...)

	for _, c := range allClients {
		c.clientCancel()
	}
	for _, c := range allClients {
		if c.client != nil {
			log.Info("Waiting for client to shut down.")
			c.client.Finished.Wait()
			log.Info("Done waiting for client to shut down.")
		}
	}

	h.ServerCancel()
	log.Info("Waiting for server to shut down")
	h.Server.Finished.Wait()
	log.Info("Done waiting for server to shut down")
	h.cacheCancel()
}

func (h *ServerHarness) CreateNoOpClient(id interface{}, syncType syncproto.SyncerType) *ClientState {
	c := h.createClient(id, syncclient.Options{SyncerType: syncType, DebugDiscardKVUpdates: true}, NoOpCallbacks{})
	h.NoOpClientStates = append(h.ClientStates, c)
	return c
}

func (h *ServerHarness) CreateClient(id interface{}, syncType syncproto.SyncerType) *ClientState {
	recorder := NewRecorder()
	c := h.createClient(id, syncclient.Options{SyncerType: syncType}, recorder)
	c.recorder = recorder
	go recorder.Loop(c.clientCxt)
	h.ClientStates = append(h.ClientStates, c)
	return c
}

func (h *ServerHarness) CreateClientNoDecodeRestart(id interface{}, syncType syncproto.SyncerType) *ClientState {
	recorder := NewRecorder()
	c := h.createClient(id, syncclient.Options{SyncerType: syncType, DisableDecoderRestart: true}, recorder)
	c.recorder = recorder
	go recorder.Loop(c.clientCxt)
	h.ClientStates = append(h.ClientStates, c)
	return c
}

func (h *ServerHarness) CreateNoOpClientNoDecodeRestart(id interface{}, syncType syncproto.SyncerType) *ClientState {
	c := h.createClient(id, syncclient.Options{SyncerType: syncType, DisableDecoderRestart: true, DebugDiscardKVUpdates: true}, NoOpCallbacks{})
	h.NoOpClientStates = append(h.ClientStates, c)
	return c
}

func (h *ServerHarness) ExpectAllClientsToReachState(status api.SyncStatus, kvs map[string]api.Update) {
	var wg sync.WaitGroup
	for _, s := range h.ClientStates {
		wg.Add(1)
		go func(s *ClientState) {
			defer wg.Done()
			defer GinkgoRecover()
			// Wait until we reach that state.
			Eventually(s.recorder.Status, 60*time.Second, 50*time.Millisecond).Should(Equal(status))
			Eventually(s.recorder.KVCompareFn(kvs), 20*time.Second, 200*time.Millisecond).ShouldNot(HaveOccurred())
		}(s)
	}
	wg.Wait()
}

func (h *ServerHarness) createClient(id interface{}, options syncclient.Options, callbacks api.SyncerCallbacks) *ClientState {
	clientCxt, clientCancel := context.WithCancel(context.Background())
	serverAddr := fmt.Sprintf("127.0.0.1:%d", h.Server.Port())
	client := syncclient.New(
		[]discovery.Typha{{Addr: serverAddr}},
		"test-version",
		fmt.Sprintf("test-host-%v", id),
		"test-info",
		callbacks,
		&options,
	)

	err := client.Start(clientCxt)
	Expect(err).NotTo(HaveOccurred())

	cs := &ClientState{
		clientCxt:    clientCxt,
		client:       client,
		clientCancel: clientCancel,
		syncerType:   options.SyncerType,
	}
	return cs
}

func (h *ServerHarness) CreateNoOpClients(n int) {
	for i := 0; i < n; i++ {
		h.CreateNoOpClient(i, syncproto.SyncerTypeFelix)
	}
}

func (h *ServerHarness) CreateNoOpClientsNoDecodeRestart(n int) {
	for i := 0; i < n; i++ {
		h.CreateNoOpClientNoDecodeRestart(i, syncproto.SyncerTypeFelix)
	}
}

func (h *ServerHarness) CreateClients(n int) {
	for i := 0; i < n; i++ {
		h.CreateClient(i, syncproto.SyncerTypeFelix)
	}
}

func (h *ServerHarness) SendStatus(s api.SyncStatus) {
	h.Decoupler.OnStatusUpdated(s)
}

func (h *ServerHarness) SendInitialSnapshotPods(numPods int) map[string]api.Update {
	expState := h.SendInitialSnapshotPodsNoInSync(numPods)
	h.SendStatus(api.InSync)
	return expState
}

func (h *ServerHarness) SendInitialSnapshotPodsNoInSync(numPods int) map[string]api.Update {
	h.SendStatus(api.ResyncInProgress)
	expState := h.SendPodUpdates(numPods)
	return expState
}

func (h *ServerHarness) SendPodUpdates(numPods int) map[string]api.Update {
	expectedEndState := map[string]api.Update{}
	conv := conversion.NewConverter()
	for i := 0; i < numPods; i++ {
		pod := generatePod(h.updIdx)
		h.updIdx++
		weps, err := conv.PodToWorkloadEndpoints(pod)
		Expect(err).NotTo(HaveOccurred())
		update := api.Update{
			KVPair:     *weps[0],
			UpdateType: api.UpdateTypeKVNew,
		}
		path, err := model.KeyToDefaultPath(update.Key)
		Expect(err).NotTo(HaveOccurred())
		expectedEndState[path] = update
		h.Decoupler.OnUpdates([]api.Update{update})
	}
	return expectedEndState
}

func (h *ServerHarness) SendInitialSnapshotConfigs(numConfigs int) map[string]api.Update {
	expState := h.SendInitialSnapshotConfigsNoInSync(numConfigs)
	h.SendStatus(api.InSync)
	return expState
}

func (h *ServerHarness) SendInitialSnapshotConfigsNoInSync(numConfigs int) map[string]api.Update {
	h.SendStatus(api.ResyncInProgress)
	expState := h.SendConfigUpdates(numConfigs)
	return expState
}

func (h *ServerHarness) SendConfigUpdates(n int) map[string]api.Update {
	expectedEndState := map[string]api.Update{}
	for i := 0; i < n; i++ {
		update := api.Update{
			KVPair: model.KVPair{
				Key: model.GlobalConfigKey{
					Name: fmt.Sprintf("foo%v", h.updIdx),
				},
				// Nice big value so that we can fill up the send queue.
				Value:    fmt.Sprint(h.updIdx, "=", randomHex(1000)),
				Revision: fmt.Sprintf("%v", h.updIdx),
			},
			UpdateType: api.UpdateTypeKVNew,
		}
		h.updIdx++
		path, err := model.KeyToDefaultPath(update.Key)
		Expect(err).NotTo(HaveOccurred())
		expectedEndState[path] = update
		h.Decoupler.OnUpdates([]api.Update{update})
	}
	return expectedEndState
}

func generatePod(n int) *corev1.Pod {
	namespace := fmt.Sprintf("a-namespace-name-%x", n/100)
	var buf [8]byte
	rand.Read(buf[:])
	name := fmt.Sprintf("some-app-name-%d-%x", n, buf[:])
	hostname := fmt.Sprintf("hostname%d", n/20)
	ip := net.IP{0, 0, 0, 0}
	binary.BigEndian.PutUint32(ip, uint32(n))
	ip[0] = 10
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				"cni.projectcalico.org/containerID": randomHex(64),
				"cni.projectcalico.org/podIP":       fmt.Sprintf("%s,/32", ip.String()),
				"cni.projectcalico.org/podIPs":      fmt.Sprintf("%s,/32", ip.String()),
			},
			Labels: map[string]string{
				"kubernetes-topology-label": "zone-A",
				"kubernetes-region-label":   "zone-A",
				"owner":                     "someone-" + randomHex(4),
				"oneof10":                   fmt.Sprintf("value-%d", n/10),
				"oneof100":                  fmt.Sprintf("value-%d", n/100),
			},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  fmt.Sprintf("container-%s", name),
			Image: "ignore",
		}},
			NodeName: hostname,
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodScheduled,
				Status: corev1.ConditionTrue,
			}},
			PodIP:  ip.String(),
			PodIPs: []corev1.PodIP{{IP: ip.String()}},
		},
	}
	return p
}

func randomHex(length int) string {
	buf := make([]byte, length/2)
	rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}

type NoOpCallbacks struct {
}

func (n NoOpCallbacks) OnStatusUpdated(_ api.SyncStatus) {
}

func (n NoOpCallbacks) OnUpdates(_ []api.Update) {
}
