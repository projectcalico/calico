// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
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

package endpoint

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

type subnetType string

const (
	PrivateNet subnetType = "pvt"
	PublicNet  subnetType = "pub"

	namespaceGlobal = "-"
)

// TODO: Import the types from Linseed instead.
type Type string

const (
	Wep Type = "wep"
	Hep Type = "hep"
	Ns  Type = "ns"
	Net Type = "net"
)

type Metadata struct {
	Type           Type   `json:"type"`
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	AggregatedName string `json:"aggregated_name"`
}

func GetLabels(ed calc.EndpointData) uniquelabels.Map {
	var labels uniquelabels.Map
	if ed != nil {
		labels = ed.Labels()
	}
	if labels.IsNil() {
		// Explicitly don't want to return nil so that we can tell if the
		// field is populated.
		labels = uniquelabels.Empty
	}
	return labels
}

func GetMetadata(ed calc.EndpointData, ip [16]byte) (Metadata, error) {
	var em Metadata
	if ed == nil {
		return Metadata{
			Type:           Net,
			Namespace:      utils.FieldNotIncluded,
			Name:           utils.FieldNotIncluded,
			AggregatedName: string(getSubnetType(ip)),
		}, nil
	}

	key := ed.Key()
	switch k := key.(type) {
	case model.WorkloadEndpointKey:
		ns, name, err := deconstructNamespaceAndNameFromWepName(k.WorkloadID)
		if err != nil {
			return Metadata{}, err
		}
		var aggName string
		gn := ed.GenerateName()
		if gn != "" {
			aggName = gn + "*"
		} else {
			aggName = name
		}
		em = Metadata{
			Type:           Wep,
			Name:           name,
			AggregatedName: aggName,
			Namespace:      ns,
		}
	case model.HostEndpointKey:
		em = Metadata{
			Type:           Hep,
			Name:           k.EndpointID,
			AggregatedName: k.Hostname,
			Namespace:      namespaceGlobal,
		}
	case model.NetworkSetKey:
		namespace, name := utils.ExtractNamespaceFromNetworkSet(k.Name)
		// No Endpoint was found so instead, a NetworkSet was returned.
		em = Metadata{
			Type:           Ns,
			Namespace:      namespace,
			AggregatedName: name,
			Name:           name,
		}
	default:
		return Metadata{}, fmt.Errorf("unknown key %#v of type %v", key, reflect.TypeOf(key))
	}

	return em, nil
}

func getSubnetType(addrBytes [16]byte) subnetType {
	IP := net.IP(addrBytes[:16])
	// Currently checking for only private blocks
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	isPrivateIP := private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
	if isPrivateIP {
		return PrivateNet
	}
	return PublicNet
}

func deconstructNamespaceAndNameFromWepName(wepName string) (string, string, error) {
	parts := strings.Split(wepName, "/")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf("could not parse name %v", wepName)
}
