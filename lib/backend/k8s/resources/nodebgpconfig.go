// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	"k8s.io/client-go/kubernetes"
)

const (
	perNodeBgpConfigAnnotationNamespace = "config.bgp.projectcalico.org"
)

func NewNodeBGPConfigClient(c *kubernetes.Clientset) K8sNodeResourceClient {
	return NewCustomK8sNodeResourceClient(CustomK8sNodeResourceClientConfig{
		ClientSet:    c,
		ResourceType: "NodeBGPConfig",
		Converter:    NodeBGPConfigConverter{},
		Namespace:    perNodeBgpConfigAnnotationNamespace,
	})
}

// NodeBGPConfigConverter implements the CustomK8sNodeResourceConverter interface.
type NodeBGPConfigConverter struct{}

func (_ NodeBGPConfigConverter) ListInterfaceToNodeAndName(l model.ListInterface) (string, string, error) {
	pl := l.(model.NodeBGPConfigListOptions)
	if pl.Name == "" {
		return pl.Nodename, "", nil
	} else {
		return pl.Nodename, pl.Name, nil
	}
}

func (_ NodeBGPConfigConverter) KeyToNodeAndName(k model.Key) (string, string, error) {
	pk := k.(model.NodeBGPConfigKey)
	return pk.Nodename, pk.Name, nil
}

func (_ NodeBGPConfigConverter) NodeAndNameToKey(node, name string) (model.Key, error) {
	return model.NodeBGPConfigKey{
		Nodename: node,
		Name:     name,
	}, nil
}
