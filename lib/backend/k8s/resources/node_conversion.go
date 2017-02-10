// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package resources

import (
	"errors"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/Sirupsen/logrus"
)

func K8sNodeToCalico(node *kapiv1.Node) (*model.KVPair, error) {
	// Get the internal IP of the node, should be 1-1 with calico node IP
	nodeIP := ""
	for _, address := range node.Status.Addresses {
		if address.Type == kapiv1.NodeInternalIP {
			nodeIP = address.Address
			log.Debugf("Found NodeInternalIP %s", nodeIP)
			break
		}
	}

	ip := net.ParseIP(nodeIP)
	log.Debugf("Node IP is %s", ip)
	if ip == nil {
		return nil, errors.New("Invalid IP received from k8s for Node")
	}
	asn := numorstring.ASNumber(64512)
	return &model.KVPair{
		Key: model.NodeKey{
			Hostname: node.Name,
		},
		Value: &model.Node{
			FelixIPv4:   ip,
			Labels:      node.Labels,
			BGPIPv4Addr:     ip,
			BGPIPv6Addr:     &net.IP{},
			BGPASNumber: &asn,
		},
		Revision: node.ObjectMeta.ResourceVersion,
	}, nil
}