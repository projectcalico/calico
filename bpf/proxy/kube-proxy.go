// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/routes"
)

// KubeProxy is a wrapper of Proxy that deals with higher level issue like
// configuration, restarting etc.
type KubeProxy struct {
	proxy Proxy

	hostIPUpdates chan []net.IP
	stopOnce      sync.Once
	lock          sync.Mutex
	exiting       chan struct{}
	wg            sync.WaitGroup

	k8s         kubernetes.Interface
	hostname    string
	frontendMap bpf.Map
	backendMap  bpf.Map
	affinityMap bpf.Map
	rt          *RTCache
	opts        []Option
}

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8s kubernetes.Interface, hostname string,
	frontendMap, backendMap, affinityMap bpf.Map, opts ...Option) (*KubeProxy, error) {

	kp := &KubeProxy{
		k8s:         k8s,
		hostname:    hostname,
		frontendMap: frontendMap,
		backendMap:  backendMap,
		affinityMap: affinityMap,
		opts:        opts,
		rt:          NewRTCache(),

		hostIPUpdates: make(chan []net.IP, 1),
		exiting:       make(chan struct{}),
	}

	go func() {
		err := kp.start()
		if err != nil {
			log.Panic("kube-proxy failed to start")
		}
	}()

	return kp, nil
}

// Stop stops KubeProxy and waits for it to exit
func (kp *KubeProxy) Stop() {
	kp.stopOnce.Do(func() {
		kp.lock.Lock()
		defer kp.lock.Unlock()

		close(kp.exiting)
		close(kp.hostIPUpdates)
		kp.proxy.Stop()
		kp.wg.Wait()
	})
}

func (kp *KubeProxy) run(hostIPs []net.IP) error {

	kp.lock.Lock()
	defer kp.lock.Unlock()

	withLocalNP := make([]net.IP, len(hostIPs), len(hostIPs)+1)
	copy(withLocalNP, hostIPs)
	withLocalNP = append(withLocalNP, podNPIP)

	syncer, err := NewSyncer(withLocalNP, kp.frontendMap, kp.backendMap, kp.affinityMap, kp.rt)
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	proxy, err := New(kp.k8s, syncer, kp.hostname, kp.opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	log.Infof("kube-proxy started, hostname=%q hostIPs=%+v", kp.hostname, hostIPs)

	kp.proxy = proxy

	return nil
}

func (kp *KubeProxy) start() error {

	// wait for the initial update
	hostIPs := <-kp.hostIPUpdates

	err := kp.run(hostIPs)
	if err != nil {
		return err
	}

	kp.wg.Add(1)
	go func() {
		defer kp.wg.Done()
		for {
			hostIPs, ok := <-kp.hostIPUpdates
			if !ok {
				defer log.Error("kube-proxy stopped since hostIPUpdates closed")
				kp.proxy.Stop()
				return
			}

			stopped := make(chan struct{})

			go func() {
				defer close(stopped)
				defer log.Info("kube-proxy stopped to restart with updated host IPs")
				kp.proxy.Stop()
			}()

		waitforstop:
			for {
				select {
				case hostIPs, ok = <-kp.hostIPUpdates:
					if !ok {
						log.Error("kube-proxy: hostIPUpdates closed")
						return
					}
				case <-kp.exiting:
					log.Info("kube-proxy: exiting")
					return
				case <-stopped:
					err = kp.run(hostIPs)
					if err != nil {
						log.Panic("kube-proxy failed to start after host IPs update")
					}
					break waitforstop
				}
			}
		}
	}()

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

// OnRouteUpdate should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteUpdate(k routes.Key, v routes.Value) {
	if err := kp.rt.Update(k, v); err != nil {
		log.WithField("error", err).Error("kube-proxy: OnRouteUpdate")
	} else {
		log.WithFields(log.Fields{"key": k, "value": v}).Debug("kube-proxy: OnRouteUpdate")
	}
}

// OnRouteDelete should be used to update the internal state of routing tables
func (kp *KubeProxy) OnRouteDelete(k routes.Key) {
	_ = kp.rt.Delete(k)
	log.WithField("key", k).Debug("kube-proxy: OnRouteDelete")
}
