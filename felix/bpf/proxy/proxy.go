// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

// This boilerplate code is based on proxiers in k8s.io/kubernetes/pkg/proxy to
// allow reuse of the rest of the proxy package without change

package proxy

import (
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	k8sp "k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/apis"
	"k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/util/async"
)

// Proxy watches for updates of Services and Endpoints, maintains their mapping
// and programs it into the dataplane
type Proxy interface {
	// Stop stops the proxy and waits for its exit
	Stop()
}

// DPSyncerState groups the information passed to the DPSyncer's Apply
type DPSyncerState struct {
	SvcMap k8sp.ServicePortMap
	EpsMap k8sp.EndpointsMap
}

// DPSyncer is an interface representing the dataplane syncer that applies the
// observed changes to the dataplane
type DPSyncer interface {
	Apply(state DPSyncerState) error
	ConntrackScanStart()
	ConntrackScanEnd()
	ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP, backendPort uint16, proto uint8) bool
	Stop()
	SetTriggerFn(func())
}

type proxy struct {
	initState

	hostname string

	k8s kubernetes.Interface

	epsChanges *k8sp.EndpointChangeTracker
	svcChanges *k8sp.ServiceChangeTracker

	svcMap k8sp.ServicePortMap
	epsMap k8sp.EndpointsMap

	dpSyncer DPSyncer
	// executes periodic the dataplane updates
	runner *async.BoundedFrequencyRunner
	// ensures that only one invocation runs at any time
	runnerLck sync.Mutex
	// sets the minimal distance between to sync to avoid overloading the
	// dataplane in case of frequent changes
	minDPSyncPeriod time.Duration

	// how often to fully sync with k8s - 0 is never
	syncPeriod time.Duration

	// event recorder to update node events
	recorder        events.EventRecorder
	svcHealthServer healthcheck.ServiceHealthServer
	healthzServer   healthcheck.ProxierHealthUpdater

	stopCh   chan struct{}
	stopWg   sync.WaitGroup
	stopOnce sync.Once
}

type stoppableRunner interface {
	Run(stopCh <-chan struct{})
}

// New returns a new Proxy for the given k8s interface
func New(k8s kubernetes.Interface, dp DPSyncer, hostname string, opts ...Option) (Proxy, error) {

	if k8s == nil {
		return nil, errors.Errorf("no k8s client")
	}

	if dp == nil {
		return nil, errors.Errorf("no dataplane syncer")
	}

	p := &proxy{
		k8s:      k8s,
		dpSyncer: dp,
		hostname: hostname,
		svcMap:   make(k8sp.ServicePortMap),
		epsMap:   make(k8sp.EndpointsMap),

		recorder: new(loggerRecorder),

		minDPSyncPeriod: 30 * time.Second, // XXX revisit the default

		stopCh: make(chan struct{}),
	}

	for _, o := range opts {
		if err := o(p); err != nil {
			return nil, errors.WithMessage(err, "applying option")
		}
	}

	// We need to create the runner first as once we start getting updates, they
	// will kick it
	p.runner = async.NewBoundedFrequencyRunner("dp-sync-runner",
		p.invokeDPSyncer, p.minDPSyncPeriod, time.Hour /* XXX might be infinite? */, 1)
	dp.SetTriggerFn(p.runner.Run)

	p.svcHealthServer = healthcheck.NewServiceHealthServer(p.hostname, p.recorder, []string{"0.0.0.0/0"})

	p.epsChanges = k8sp.NewEndpointChangeTracker(p.hostname,
		nil, // change if you want to provide more ctx
		v1.IPv4Protocol,
		p.recorder,
		nil,
	)
	p.svcChanges = k8sp.NewServiceChangeTracker(nil, v1.IPv4Protocol, p.recorder, nil)

	noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
	if err != nil {
		return nil, errors.Errorf("noProxyName selector: %s", err)
	}

	noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		return nil, errors.Errorf("noHeadlessEndpoints selector: %s", err)
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	informerFactory := informers.NewSharedInformerFactoryWithOptions(k8s, p.syncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	svcConfig := config.NewServiceConfig(
		informerFactory.Core().V1().Services(),
		p.syncPeriod,
	)
	svcConfig.RegisterEventHandler(p)

	var epsRunner stoppableRunner

	epsConfig := config.NewEndpointSliceConfig(informerFactory.Discovery().V1().EndpointSlices(), p.syncPeriod)
	epsConfig.RegisterEventHandler(p)
	epsRunner = epsConfig

	p.startRoutine(func() { p.runner.Loop(p.stopCh) })
	p.startRoutine(func() { epsRunner.Run(p.stopCh) })
	p.startRoutine(func() { informerFactory.Start(p.stopCh) })
	p.startRoutine(func() { svcConfig.Run(p.stopCh) })

	return p, nil
}

func (p *proxy) Stop() {
	p.stopOnce.Do(func() {
		log.Info("Proxy stopping")
		p.dpSyncer.Stop()
		close(p.stopCh)
		p.stopWg.Wait()
		log.Info("Proxy stopped")
	})
}

func (p *proxy) startRoutine(f func()) {
	p.stopWg.Add(1)
	go func() {
		defer p.stopWg.Done()
		f()
	}()
}

func (p *proxy) syncDP() {
	p.runner.Run()
}

func (p *proxy) forceSyncDP() {
	p.invokeDPSyncer()
}

func (p *proxy) invokeDPSyncer() {
	if !p.isInitialized() {
		return
	}

	p.runnerLck.Lock()
	defer p.runnerLck.Unlock()

	svcUpdateResult := p.svcMap.Update(p.svcChanges)
	epsUpdateResult := p.epsMap.Update(p.epsChanges)

	if err := p.svcHealthServer.SyncServices(svcUpdateResult.HCServiceNodePorts); err != nil {
		log.WithError(err).Error("Error syncing healthcheck services")
	}
	if err := p.svcHealthServer.SyncEndpoints(epsUpdateResult.HCEndpointsLocalIPSize); err != nil {
		log.WithError(err).Error("Error syncing healthcheck endpoints")
	}

	err := p.dpSyncer.Apply(DPSyncerState{
		SvcMap: p.svcMap,
		EpsMap: p.epsMap,
	})

	if err != nil {
		log.WithError(err).Errorf("applying changes failed")
		// TODO log the error or panic as the best might be to restart
		// completely to wipe out the loaded bpf maps
	}

	if p.healthzServer != nil {
		p.healthzServer.Updated()
	}
}

func (p *proxy) OnServiceAdd(svc *v1.Service) {
	p.OnServiceUpdate(nil, svc)
}

func (p *proxy) OnServiceUpdate(old, curr *v1.Service) {
	if p.svcChanges.Update(old, curr) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnServiceDelete(svc *v1.Service) {
	p.OnServiceUpdate(svc, nil)
}

func (p *proxy) OnServiceSynced() {
	p.setSvcsSynced()
	p.forceSyncDP()
}

func (p *proxy) OnEndpointsAdd(eps *v1.Endpoints) {
	p.OnEndpointsUpdate(nil, eps)
}

func (p *proxy) OnEndpointsUpdate(old, curr *v1.Endpoints) {
	if p.epsChanges.Update(old, curr) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointsDelete(eps *v1.Endpoints) {
	p.OnEndpointsUpdate(eps, nil)
}

func (p *proxy) OnEndpointsSynced() {
	p.setEpsSynced()
	p.forceSyncDP()
}

func (p *proxy) OnEndpointSliceAdd(eps *discovery.EndpointSlice) {
	if p.epsChanges.EndpointSliceUpdate(eps, false) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSliceUpdate(_, eps *discovery.EndpointSlice) {
	if p.epsChanges.EndpointSliceUpdate(eps, false) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSliceDelete(eps *discovery.EndpointSlice) {
	if p.epsChanges.EndpointSliceUpdate(eps, true) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSlicesSynced() {
	p.setEpsSynced()
	p.forceSyncDP()
}

type initState struct {
	lck        sync.RWMutex
	svcsSynced bool
	epsSynced  bool
}

func (is *initState) isInitialized() bool {
	is.lck.RLock()
	defer is.lck.RUnlock()
	return is.svcsSynced && is.epsSynced
}

func (is *initState) setSvcsSynced() {
	is.lck.Lock()
	defer is.lck.Unlock()
	is.svcsSynced = true
}

func (is *initState) setEpsSynced() {
	is.lck.Lock()
	defer is.lck.Unlock()
	is.epsSynced = true
}

type loggerRecorder struct{}

func (r *loggerRecorder) Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
}
