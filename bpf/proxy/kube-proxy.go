// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.
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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"net"

	"github.com/projectcalico/felix/bpf"
)

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8s kubernetes.Interface, hostname string,
	frontendMap, backendMap bpf.Map, hostIPUpdates <-chan []net.IP,
	opts ...Option) error {
	go func() {
		err := startKubeProxy(k8s, hostname, frontendMap, backendMap, hostIPUpdates, opts...)
		if err != nil {
			log.Panic("kube-proxy failed to start")
		}
	}()

	return nil
}

func runKubeProxy(k8s kubernetes.Interface, hostname string,
	frontendMap, backendMap bpf.Map, hostIPs []net.IP,
	opts ...Option) (Proxy, error) {

	syncer, err := NewSyncer(hostIPs, frontendMap, backendMap)
	if err != nil {
		return nil, errors.WithMessage(err, "new bpf syncer")
	}

	proxy, err := New(k8s, syncer, hostname, opts...)
	if err != nil {
		return nil, errors.WithMessage(err, "new proxy")
	}

	log.Infof("kube-proxy started, hostname=%q hostIPs=%+v", hostname, hostIPs)

	return proxy, nil
}

func startKubeProxy(k8s kubernetes.Interface, hostname string,
	frontendMap, backendMap bpf.Map, hostIPUpdates <-chan []net.IP,
	opts ...Option) error {

	// wait for the initial update
	hostIPs := <-hostIPUpdates

	p, err := runKubeProxy(k8s, hostname, frontendMap, backendMap, hostIPs, opts...)
	if err != nil {
		return err
	}

	go func() {
		for {
			hostIPs, ok := <-hostIPUpdates
			if !ok {
				defer log.Error("kube-proxy stopped since hostIPUpdates closed")
				p.Stop()
				return
			}

			stopped := make(chan struct{})

			go func() {
				defer close(stopped)
				defer log.Info("kube-proxy stopped to restart with updated host IPs")
				p.Stop()
			}()

		waitforstop:
			for {
				select {
				case hostIPs, ok = <-hostIPUpdates:
					if !ok {
						log.Error("kube-proxy: hostIPUpdates closed")
						return
					}
				case <-stopped:
					p, err = runKubeProxy(k8s, hostname, frontendMap, backendMap, hostIPs, opts...)
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
