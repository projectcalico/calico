// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"net"
	"strings"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
	k8sp "k8s.io/kubernetes/pkg/proxy"
	"k8s.io/kubernetes/pkg/proxy/apis"
	"k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/healthcheck"
	"k8s.io/kubernetes/pkg/proxy/runner"
	"k8s.io/kubernetes/pkg/proxy/util"

	"github.com/projectcalico/calico/felix/proto"
)

// Proxy watches for updates of Services and Endpoints, maintains their mapping
// and programs it into the dataplane
type Proxy interface {
	// Stop stops the proxy and waits for its exit
	Stop()

	setIpFamily(int)
}

type ProxyFrontend interface {
	Proxy
	SetSyncer(DPSyncer)
	SetHostIPs([]net.IP)
	SetHostMetadata(updates map[string]*proto.HostMetadataV4V6Update, requestResync bool)
}

// DPSyncerState groups the information passed to the DPSyncer's Apply
type DPSyncerState struct {
	SvcMap   k8sp.ServicePortMap
	EpsMap   k8sp.EndpointsMap
	Hostname string
	NodeZone string
}

// DPSyncer is an interface representing the dataplane syncer that applies the
// observed changes to the dataplane
type DPSyncer interface {
	Apply(state DPSyncerState) error
	ConntrackScanStart()
	ConntrackScanEnd()
	ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP, backendPort uint16, proto uint8) bool
	ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool
	Stop()
	SetTriggerFn(func())
	HasSynced() bool
}

type proxy struct {
	initState

	hostname string
	nodeZone string
	k8s      kubernetes.Interface
	ipFamily int

	epsChanges *k8sp.EndpointsChangeTracker
	svcChanges *k8sp.ServiceChangeTracker

	svcMap k8sp.ServicePortMap
	epsMap k8sp.EndpointsMap

	hostMetadataByHostname map[string]*proto.HostMetadataV4V6Update

	dpSyncer  DPSyncer
	syncerLck sync.Mutex
	// executes periodic the dataplane updates
	runner *runner.BoundedFrequencyRunner
	// ensures that only one invocation runs at any time
	runnerLck sync.Mutex
	// sets the minimal distance between to sync to avoid overloading the
	// dataplane in case of frequent changes
	minDPSyncPeriod time.Duration

	// The interval that syncing is guaranteed to run even without any other triggers.
	maxDPSyncPeriod time.Duration

	// The interval to retry syncing.
	retryDPSyncPeriod time.Duration

	// how often to fully sync with k8s - 0 is never
	syncPeriod time.Duration

	// event recorder to update node events
	recorder        events.EventRecorder
	svcHealthServer healthcheck.ServiceHealthServer
	healthzServer   Healthcheck

	stopCh   chan struct{}
	stopWg   sync.WaitGroup
	stopOnce sync.Once
}

type stoppableRunner interface {
	Run(stopCh <-chan struct{})
}

// New returns a new Proxy for the given k8s interface
func New(k8s kubernetes.Interface, dp DPSyncer, hostname string, opts ...Option) (ProxyFrontend, error) {

	if k8s == nil {
		return nil, errors.New("no k8s client")
	}

	if dp == nil {
		return nil, errors.New("no dataplane syncer")
	}

	p := &proxy{
		k8s:      k8s,
		dpSyncer: dp,
		hostname: hostname,
		ipFamily: 4,
		svcMap:   make(k8sp.ServicePortMap),
		epsMap:   make(k8sp.EndpointsMap),

		hostMetadataByHostname: make(map[string]*proto.HostMetadataV4V6Update),

		recorder: new(loggerRecorder),

		// TODO: revisit these default values.
		minDPSyncPeriod:   30 * time.Second,
		maxDPSyncPeriod:   1 * time.Hour,
		retryDPSyncPeriod: 1 * time.Hour, // XXX might be infinite?

		stopCh:        make(chan struct{}),
		healthzServer: new(alwaysHealthy),
		// N.B. we do not start healthzServer until we have at least some host
		// IPs. Dataplane implementation of hostports assumes we have a host IP.
	}

	for _, o := range opts {
		if err := o(p); err != nil {
			return nil, errors.WithMessage(err, "applying option")
		}
	}

	// We need to create the runner first as once we start getting updates, they
	// will kick it
	p.runner = runner.NewBoundedFrequencyRunner("dp-sync-runner",
		p.invokeDPSyncer, p.minDPSyncPeriod, p.retryDPSyncPeriod, p.maxDPSyncPeriod)
	dp.SetTriggerFn(p.runner.Run)

	ipVersion := p.v1IPFamily()

	p.epsChanges = k8sp.NewEndpointsChangeTracker(ipVersion, p.hostname, nil, nil)
	p.svcChanges = k8sp.NewServiceChangeTracker(ipVersion, makeServiceInfo, nil)

	noProxyName, err := labels.NewRequirement(apis.LabelServiceProxyName, selection.DoesNotExist, nil)
	if err != nil {
		return nil, fmt.Errorf("noProxyName selector: %s", err)
	}

	noHeadlessEndpoints, err := labels.NewRequirement(v1.IsHeadlessService, selection.DoesNotExist, nil)
	if err != nil {
		return nil, fmt.Errorf("noHeadlessEndpoints selector: %s", err)
	}

	labelSelector := labels.NewSelector()
	labelSelector = labelSelector.Add(*noProxyName, *noHeadlessEndpoints)

	informerFactory := informers.NewSharedInformerFactoryWithOptions(k8s, p.syncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.LabelSelector = labelSelector.String()
		}))

	svcConfig := config.NewServiceConfig(
		context.TODO(),
		informerFactory.Core().V1().Services(),
		p.syncPeriod,
	)
	svcConfig.RegisterEventHandler(p)

	var epsRunner stoppableRunner

	epsConfig := config.NewEndpointSliceConfig(context.TODO(), informerFactory.Discovery().V1().EndpointSlices(), p.syncPeriod)
	epsConfig.RegisterEventHandler(p)
	epsRunner = epsConfig

	p.startRoutine(func() { p.runner.Loop(p.stopCh) })
	p.startRoutine(func() { epsRunner.Run(p.stopCh) })
	p.startRoutine(func() { informerFactory.Start(p.stopCh) })
	p.startRoutine(func() { svcConfig.Run(p.stopCh) })

	return p, nil
}

func (p *proxy) v1IPFamily() v1.IPFamily {
	pr := v1.IPv4Protocol
	if p.ipFamily != 4 {
		pr = v1.IPv6Protocol
	}

	return pr
}

func (p *proxy) setIpFamily(ipFamily int) {
	p.ipFamily = ipFamily
}

func (p *proxy) Stop() {
	p.stopOnce.Do(func() {
		log.Info("Proxy stopping")
		// Pass empty update to close all the health checks.
		p.stopSvcHealthServer()
		p.dpSyncer.Stop()
		close(p.stopCh)
		p.stopWg.Wait()
		log.Info("Proxy stopped")
	})
}

func (p *proxy) startRoutine(f func()) {
	p.stopWg.Go(func() {
		f()
	})
}

func (p *proxy) syncDP() {
	p.runner.Run()
}

func (p *proxy) forceSyncDP() {
	err := p.invokeDPSyncer()
	if err != nil {
		log.WithError(err).Error("Failed invoking dataplane syncer")
	}
}

func (p *proxy) invokeDPSyncer() error {
	if !p.isInitialized() {
		return fmt.Errorf("proxy is not initialized")
	}

	p.runnerLck.Lock()
	defer p.runnerLck.Unlock()

	_ = p.svcMap.Update(p.svcChanges)
	_ = p.epsMap.Update(p.epsChanges)

	if p.healthzServer != nil && p.svcHealthServer != nil {
		if err := p.svcHealthServer.SyncServices(p.svcMap.HealthCheckNodePorts()); err != nil {
			return fmt.Errorf("error syncing healthcheck Services - err: %w", err)
		}
		if err := p.svcHealthServer.SyncEndpoints(p.epsMap.LocalReadyEndpoints()); err != nil {
			return fmt.Errorf("error syncing healthcheck endpoints - err: %w", err)
		}
	}

	if p.healthzServer != nil {
		p.healthzServer.QueuedUpdate(p.v1IPFamily())
	}

	p.syncerLck.Lock()
	err := p.dpSyncer.Apply(DPSyncerState{
		SvcMap:   p.svcMap,
		EpsMap:   p.epsMap,
		Hostname: p.hostname,
		NodeZone: p.nodeZone,
	})
	p.syncerLck.Unlock()

	if err != nil {
		// TODO log the error or panic as the best might be to restart
		// completely to wipe out the loaded bpf maps
		return fmt.Errorf("applying changes failed - err: %w", err)
	}

	if p.healthzServer != nil {
		p.healthzServer.Updated(p.v1IPFamily())
	}
	return nil
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

func (p *proxy) OnEndpointSliceAdd(eps *discovery.EndpointSlice) {
	if p.IPFamily() != eps.AddressType {
		return
	}
	if p.epsChanges.EndpointSliceUpdate(eps, false) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSliceUpdate(_, eps *discovery.EndpointSlice) {
	if p.IPFamily() != eps.AddressType {
		return
	}
	if p.epsChanges.EndpointSliceUpdate(eps, false) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSliceDelete(eps *discovery.EndpointSlice) {
	if p.IPFamily() != eps.AddressType {
		return
	}
	if p.epsChanges.EndpointSliceUpdate(eps, true) && p.isInitialized() {
		p.syncDP()
	}
}

func (p *proxy) OnEndpointSlicesSynced() {
	p.setEpsSynced()
	p.forceSyncDP()
}

func (p *proxy) SetSyncer(s DPSyncer) {
	p.syncerLck.Lock()
	p.dpSyncer.Stop()
	p.dpSyncer = s
	p.syncerLck.Unlock()

	p.forceSyncDP()
}

func (p *proxy) stopSvcHealthServer() {
	if p.svcHealthServer != nil {
		_ = p.svcHealthServer.SyncServices(map[types.NamespacedName]uint16{})
		_ = p.svcHealthServer.SyncEndpoints(map[types.NamespacedName]int{})
	}
}

func (p *proxy) SetHostIPs(hostIPs []net.IP) {
	p.runnerLck.Lock()
	defer p.runnerLck.Unlock()

	p.stopSvcHealthServer()

	ips := make([]string, 0, len(hostIPs))
	for _, ip := range hostIPs {
		if ip.To4() != nil && p.ipFamily == 4 {
			ips = append(ips, ip.String()+"/32")
		} else if ip.To4() == nil && p.ipFamily != 4 {
			ips = append(ips, ip.String()+"/128")
		}
	}

	npa := util.NewNodePortAddresses(p.v1IPFamily(), ips)
	log.Infof("NodePortAddresses V%d for health checks: %s", p.ipFamily, npa.String())
	p.svcHealthServer = healthcheck.NewServiceHealthServer(p.hostname, p.recorder,
		npa, p.healthzServer)
}

func (p *proxy) SetHostMetadata(updates map[string]*proto.HostMetadataV4V6Update, requestResync bool) {
	p.runnerLck.Lock()
	defer p.runnerLck.Unlock()

	// Clear the proxy's map and repopulate.
	for k := range p.hostMetadataByHostname {
		delete(p.hostMetadataByHostname, k)
	}

	for k, v := range updates {
		p.hostMetadataByHostname[k] = v
	}

	if requestResync {
		// Invoke a sync via the runner, so that we can release any locks in this goroutine.
		p.syncDP()
	}
}

func (p *proxy) IPFamily() discovery.AddressType {
	if p.ipFamily == 4 {
		return discovery.AddressTypeIPv4
	}
	return discovery.AddressTypeIPv6
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

func (r *loggerRecorder) Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...any) {
}

const (
	ReapTerminatingUDPAnnotation   = "projectcalico.org/udpConntrackCleanup"
	ReapTerminatingUDPImmediatelly = "TerminatingImmediately"

	ExcludeServiceAnnotation          = "projectcalico.org/natExcludeService"
	ExternalTrafficStrategyAnnotation = "lb.projectcalico.org/external-traffic-strategy"
)

var (
	ExternalTrafficStrategyMaglev = "maglev"
)

type ServiceAnnotations interface {
	ReapTerminatingUDP() bool
	ExcludeService() bool
	UseMaglev() bool
	TopologyMode() string
}

type servicePortAnnotations struct {
	reapTerminatingUDP bool
	excludeService     bool
	useMaglev          bool
	topologyMode       string
}

func (s *servicePortAnnotations) ReapTerminatingUDP() bool {
	return s.reapTerminatingUDP
}

func (s *servicePortAnnotations) ExcludeService() bool {
	return s.excludeService
}

func (s *servicePortAnnotations) UseMaglev() bool {
	return s.useMaglev
}

func (s *servicePortAnnotations) TopologyMode() string {
	return s.topologyMode
}

type servicePort struct {
	k8sp.ServicePort
	servicePortAnnotations
}

func makeServiceInfo(_ *v1.ServicePort, s *v1.Service, baseSvc *k8sp.BaseServicePortInfo) k8sp.ServicePort {
	svc := &servicePort{
		ServicePort: baseSvc,
	}

	if v, ok := s.Annotations[ExcludeServiceAnnotation]; ok && v == "true" {
		svc.excludeService = true
		goto out
	}

	if baseSvc.Protocol() == v1.ProtocolUDP {
		if v, ok := s.Annotations[ReapTerminatingUDPAnnotation]; ok && strings.EqualFold(v, ReapTerminatingUDPImmediatelly) {
			svc.reapTerminatingUDP = true
		}
	}

	if a, ok := s.Annotations[ExternalTrafficStrategyAnnotation]; ok && strings.EqualFold(a, ExternalTrafficStrategyMaglev) {
		svc.useMaglev = true
	}

	if v, ok := s.Annotations[v1.AnnotationTopologyMode]; ok {
		svc.topologyMode = v
	}

out:
	return svc
}
