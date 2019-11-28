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
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/felix/bpf"
)

// StartKubeProxy start a new kube-proxy if there was no error
func StartKubeProxy(k8sClientSet *kubernetes.Clientset, hostname string, frontendMap, backendMap bpf.Map, opts ...Option) error {
	hostIPs, err := getHostIPs()
	if err != nil {
		return err
	}

	syncer, err := NewSyncer(hostIPs, frontendMap, backendMap)
	if err != nil {
		return errors.WithMessage(err, "new bpf syncer")
	}

	_, err = New(k8sClientSet, syncer, hostname, opts...)
	if err != nil {
		return errors.WithMessage(err, "new proxy")
	}

	log.Infof("kube-proxy started, hostname=%q hostIP=%+v", hostname, hostIPs)

	return nil
}

func getHostIPs() ([]net.IP, error) {
	nl, err := netlink.NewHandle()
	if err != nil {
		return nil, errors.Errorf("failed to create netlink handle: %s", err)
	}

	eth0, err := nl.LinkByName("eth0")
	if err != nil {
		return nil, errors.Errorf("failed to find eth0: %s", err)
	}

	addrs, err := netlink.AddrList(eth0, 0)
	if err != nil {
		return nil, errors.Errorf("failed to list eth0 addrs: %s", err)
	}

	var ret []net.IP

	for _, a := range addrs {
		if a.IPNet != nil {
			if ipv4 := a.IP.To4(); ipv4 != nil {
				ret = append(ret, ipv4)
			}
		}
	}

	return ret, nil
}
