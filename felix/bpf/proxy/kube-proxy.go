// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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

package proxy

import (
	"net"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

// KubeProxy is a wrapper of Proxy that deals with higher level issue like
// configuration, restarting etc.
type KubeProxy struct {
	proxy  ProxyFrontend
	syncer DPSyncer

	// pendingHostMetadataUpdates contains HostMetadataV4V6Update and HostMetadataV4V6Removes
	// that we're batching up to send. Only accessed from the int-dataplane goroutine.
	// Keyed by hostname (node name).
	pendingHostMetadataUpdates map[string]any
	// hostMetadataUpdates is a size-1 channel - allows for one non-blocking write,
	// and repeated updates get merged into older unconsumed ones.
	hostMetadataUpdates    chan map[string]any
	inSyncWithIntDataplane bool

	ipFamily      int
	hostIPUpdates chan []net.IP
	stopOnce      sync.Once
	lock          sync.RWMutex
	exiting       chan struct{}
	wg            sync.WaitGroup

	k8s           kubernetes.Interface
	hostname      string
	frontendMap   maps.MapWithExistsCheck
	backendMap    maps.MapWithExistsCheck
	MaglevMap     maps.MapWithExistsCheck
	maglevLUTSize int
	affinityMap   maps.Map
	ctMap         maps.Map
	rt            *RTCache
	opts          []Option

	excludedCIDRs *ip.CIDRTrie

	dsrEnabled bool
}

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8s kubernetes.Interface, hostname string,
	bpfMaps *bpfmap.IPMaps, opts ...Option) (*KubeProxy, error) {

	kp := &KubeProxy{
		k8s:         k8s,
		ipFamily:    4,
		hostname:    hostname,
		frontendMap: bpfMaps.FrontendMap.(maps.MapWithExistsCheck),
		backendMap:  bpfMaps.BackendMap.(maps.MapWithExistsCheck),
		MaglevMap:   bpfMaps.MaglevMap.(maps.MapWithExistsCheck),
		affinityMap: bpfMaps.AffinityMap,
		ctMap:       bpfMaps.CtMap,
		opts:        opts,
		rt:          NewRTCache(),

		hostMetadataUpdates:        make(chan map[string]any, 1),
		pendingHostMetadataUpdates: make(map[string]any),

		hostIPUpdates: make(chan []net.IP, 1),
		exiting:       make(chan struct{}),
	}

	for _, o := range opts {
		if err := o(kp); err != nil {
			return nil, errors.WithMessage(err, "applying option to kube-proxy")
		}
	}

	go func() {
		err := kp.start()
		if err != nil {
			log.WithError(err).Panic("kube-proxy failed to start")
		}
	}()

	return kp, nil
}

func (kp *KubeProxy) setIpFamily(ipFamily int) {
	kp.ipFamily = ipFamily
}

// Stop stops KubeProxy and waits for it to exit
func (kp *KubeProxy) Stop() {
	kp.stopOnce.Do(func() {
		kp.lock.Lock()
		defer kp.lock.Unlock()

		close(kp.exiting)
		close(kp.hostMetadataUpdates)
		close(kp.hostIPUpdates)
		kp.proxy.Stop()
		kp.wg.Wait()
	})
}

func (kp *KubeProxy) setProxyHostMetadata(hostMetadata map[string]*proto.HostMetadataV4V6Update) {
	kp.lock.Lock()
	defer kp.lock.Unlock()

	kp.proxy.SetHostMetadata(hostMetadata, true)
}

func (kp *KubeProxy) run(hostIPs []net.IP, hostMetadata map[string]*proto.HostMetadataV4V6Update) error {

	ips := make([]net.IP, 0, len(hostIPs))
	for _, ip := range hostIPs {
		if kp.ipFamily == 4 && ip.To4() != nil {
			ips = append(ips, ip)
		} else if kp.ipFamily == 6 && ip.To4() == nil {
			ips = append(ips, ip)
		}
	}

	hostIPs = ips

	kp.lock.Lock()
	defer kp.lock.Unlock()

	withLocalNP := make([]net.IP, len(hostIPs), len(hostIPs)+1)
	copy(withLocalNP, hostIPs)
	if kp.ipFamily == 4 {
		withLocalNP = append(withLocalNP, podNPIP)
	} else {
		withLocalNP = append(withLocalNP, podNPIPV6)
	}

	syncer, err := NewSyncer(kp.ipFamily, withLocalNP, kp.frontendMap, kp.backendMap, kp.MaglevMap, kp.affinityMap,
		kp.rt, kp.excludedCIDRs, kp.maglevLUTSize)
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	kp.proxy.SetHostIPs(hostIPs)
	// Don't bother invoking a resync within SetHostMetadata; we will be syncing a fresh syncer right after.
	kp.proxy.SetHostMetadata(hostMetadata, false)
	kp.proxy.SetSyncer(syncer)

	log.Infof("kube-proxy v%d node info updated, hostname=%q hostIPs=%+v", kp.ipFamily, kp.hostname, hostIPs)

	kp.syncer = syncer

	return nil
}

func (kp *KubeProxy) start() error {
	var withLocalNP []net.IP
	if kp.ipFamily == 4 {
		withLocalNP = append(withLocalNP, podNPIP)
	} else {
		withLocalNP = append(withLocalNP, podNPIPV6)
	}

	syncer, err := NewSyncer(kp.ipFamily, withLocalNP, kp.frontendMap, kp.backendMap, kp.MaglevMap, kp.affinityMap, kp.rt, kp.excludedCIDRs, kp.maglevLUTSize)
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	proxy, err := New(kp.k8s, syncer, kp.hostname, kp.opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	kp.lock.Lock()
	kp.proxy = proxy
	kp.syncer = syncer
	kp.lock.Unlock()

	// Wait for the initial update.
	hostIPs := <-kp.hostIPUpdates

	hostMetadata := make(map[string]*proto.HostMetadataV4V6Update)
	// Block until we go in-sync and get the first batch of hostmetadata
	// updates, to avoid a flap after a Felix restart. In practice, this
	// recv should happen very soon after receiving the host IPs above.
	hostMetadataUpdates := <-kp.hostMetadataUpdates
	mergeHostMetadataV4V6Updates(hostMetadata, hostMetadataUpdates)

	err = kp.run(hostIPs, hostMetadata)
	if err != nil {
		return err
	}

	kp.wg.Go(func() {
		for {
			var ok bool
			select {
			case hostIPs, ok = <-kp.hostIPUpdates:
				if !ok {
					log.Error("kube-proxy: hostIPUpdates closed")
					return
				}
				err = kp.run(hostIPs, hostMetadata)
				if err != nil {
					log.Panic("kube-proxy failed to resync after host IPs update")
				}

			case hostMetadataUpdates, ok = <-kp.hostMetadataUpdates:
				if !ok {
					log.Error("kube-proxy: hostMetadataUpdates closed")
					return
				}
				mergeHostMetadataV4V6Updates(hostMetadata, hostMetadataUpdates)
				kp.setProxyHostMetadata(hostMetadata)

			case <-kp.exiting:
				log.Info("kube-proxy: exiting")
				return
			}
		}
	})

	return nil
}

// OnHostIPsUpdate should be used by an external user to update the proxy's list
// of host IPs
func (kp *KubeProxy) OnHostIPsUpdate(IPs []net.IP) {
	select {
	case kp.hostIPUpdates <- IPs:
		// nothing
	default:
		// in case we would block, drop the now stale update and replace it
		// with a new one. Do it non-blocking way in case it was just consumed.
		select {
		case <-kp.hostIPUpdates:
		default:
		}
		kp.hostIPUpdates <- IPs
	}
	log.Debugf("kube-proxy OnHostIPsUpdate: %+v", IPs)
}

// OnUpdate implements the manager interface.
// Writes updates to pending updates map - overwrites repeated updates for the same key.
func (kp *KubeProxy) OnUpdate(msg any) {
	hostname := ""
	switch update := msg.(type) {
	case *proto.HostMetadataV4V6Update:
		hostname = update.Hostname
		log.WithField("msg", update).Debugf("kube-proxy OnUpdate: host metadata update")
	case *proto.HostMetadataV4V6Remove:
		hostname = update.Hostname
		log.WithField("msg", update).Debugf("kube-proxy OnUpdate: host metadata remove")
	default:
		return
	}

	if hostname == "" {
		log.WithField("msg", msg).Warn("kube-proxy OnUpdate: got host metadata update with empty hostname")
		return
	}

	kp.pendingHostMetadataUpdates[hostname] = msg
}

// CompleteDeferredWork implements the manager interface.
// Avoids blocking the thread by draining & merging older updates on the channel before sending.
func (kp *KubeProxy) CompleteDeferredWork() error {
	// If not in-sync with felix, we allow sending an empty update
	// to signal to the KP loop that it can start looping.
	if len(kp.pendingHostMetadataUpdates) == 0 && kp.inSyncWithIntDataplane {
		log.Debug("No pending host metadata updates to process")
		return nil
	}

	// Drain any pre-existing msg first and merge.
	updates := kp.pollHostMetadataV4V6UpdatesNonBlocking()
	if updates == nil {
		updates = make(map[string]any)
	}

	// Overwrite any pre-existing updates for a given key.
	// Always send 'Removes' instead of just deleting updates of the same key (since downstream may need to see a remove).
	for k, v := range kp.pendingHostMetadataUpdates {
		updates[k] = v
		log.WithField("nodeName", k).Debug("Queueing new host metadata update")
		// ... And clear the pending updates after processing.
		delete(kp.pendingHostMetadataUpdates, k)
	}

	// Send the merged updates back down the channel.
	log.Debug("Queueing new hostmetadata for main loop")
	kp.hostMetadataUpdates <- updates
	log.Debug("Successfully queued new hostmetadata")
	kp.inSyncWithIntDataplane = true
	return nil
}

// pollHostMetadataV4V6UpdatesNonBlocking tries to read a pending host metadata update on the update channel.
// Returns nil immediately, if nothing can be received from the updates channel.
func (kp *KubeProxy) pollHostMetadataV4V6UpdatesNonBlocking() map[string]any {
	select {
	case upd := <-kp.hostMetadataUpdates:
		return upd
	default:
		return nil
	}
}

// mergeHostMetadataV4V6Updates merges the existing host metadata updates with the latest updates:
// - A 'remove' in latest deletes the corresponding key in 'existing'.
// - An 'update' in latest overwrites the corresponding key in 'existing'.
// - If 'latest' is nil, does nothing. 'existing' must be non-nil.
func mergeHostMetadataV4V6Updates(existing map[string]*proto.HostMetadataV4V6Update, latest map[string]any) {
	if latest == nil {
		return
	}

	for k, v := range latest {
		switch update := v.(type) {
		case *proto.HostMetadataV4V6Update:
			existing[k] = update
		case *proto.HostMetadataV4V6Remove:
			delete(existing, k)
		}
	}
}

// OnRouteUpdate should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteUpdate(k routes.KeyInterface, v routes.ValueInterface) {
	log.WithFields(log.Fields{"key": k, "value": v}).Debug("kube-proxy: OnRouteUpdate")
	kp.rt.Update(k, v)
}

// OnRouteDelete should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteDelete(k routes.KeyInterface) {
	kp.rt.Delete(k)
	log.WithField("key", k).Debug("kube-proxy: OnRouteDelete")
}

// ConntrackScanStart to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackScanStart() {
	kp.lock.RLock()
	if kp.syncer != nil {
		kp.syncer.ConntrackScanStart()
	}
}

// ConntrackScanEnd to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackScanEnd() {
	if kp.syncer != nil {
		kp.syncer.ConntrackScanEnd()
	}
	kp.lock.RUnlock()
}

// ConntrackFrontendHasBackend to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP,
	backendPort uint16, proto uint8) bool {

	// Thanks to holding the lock since ConntrackScanStart, this condition holds for the
	// whole iteration. So if we started without syncer, we will also finish without it.
	// And if we had a syncer, we will have the same until the end.
	if kp.syncer != nil && kp.syncer.HasSynced() {
		return kp.syncer.ConntrackFrontendHasBackend(ip, port, backendIP, backendPort, proto)
	}

	// We cannot say yet, so do not break anything
	return true
}

// ConntrackDestIsService to satisfy conntrack.NATChecker - forwards to syncer.
func (kp *KubeProxy) ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool {
	if kp.syncer != nil && kp.syncer.HasSynced() {
		return kp.syncer.ConntrackDestIsService(ip, port, proto)
	}

	// We cannot say yet, so do not break anything
	return false
}
