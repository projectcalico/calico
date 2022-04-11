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

package updateprocessors

import (
	"errors"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync WorkloadEndpoint data in v1 format for
// consumption by Felix.
func NewWorkloadEndpointUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(libapiv3.KindWorkloadEndpoint, convertWorkloadEndpointV2ToV1Key, convertWorkloadEndpointV2ToV1Value)
}

func convertWorkloadEndpointV2ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	parts := names.ExtractDashSeparatedParms(v3key.Name, 4)
	if len(parts) != 4 || v3key.Namespace == "" {
		return model.WorkloadEndpointKey{}, errors.New("Not enough information provided to create v1 Workload Endpoint Key")
	}
	return model.WorkloadEndpointKey{
		Hostname:       parts[0],
		OrchestratorID: parts[1],
		WorkloadID:     v3key.Namespace + "/" + parts[2],
		EndpointID:     parts[3],
	}, nil

}

func convertWorkloadEndpointV2ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*libapiv3.WorkloadEndpoint)
	if !ok {
		return nil, errors.New("Value is not a valid WorkloadEndpoint resource value")
	}

	// If the WEP has no IPNetworks assigned then filter out since we can't yet render the rules.
	if len(v3res.Spec.IPNetworks) == 0 {
		log.WithFields(log.Fields{
			"name":      v3res.Name,
			"namespace": v3res.Namespace,
		}).Debug("Filtering out WEP with no IPNetworks")
		return nil, nil
	}

	var ipv4Nets []cnet.IPNet
	var ipv6Nets []cnet.IPNet
	for _, ipnString := range v3res.Spec.IPNetworks {
		_, ipn, err := cnet.ParseCIDROrIP(ipnString)
		if err != nil {
			return nil, err
		}
		ipnet := *(ipn.Network())
		if ipnet.Version() == 4 {
			ipv4Nets = append(ipv4Nets, ipnet)
		} else {
			ipv6Nets = append(ipv6Nets, ipnet)
		}
	}

	var ipv4NAT []model.IPNAT
	var ipv6NAT []model.IPNAT
	for _, ipnat := range v3res.Spec.IPNATs {
		nat := ConvertV2ToV1IPNAT(ipnat)
		if nat != nil {
			if nat.IntIP.Version() == 4 {
				ipv4NAT = append(ipv4NAT, *nat)
			} else {
				ipv6NAT = append(ipv6NAT, *nat)
			}
		}
	}

	var ipv4Gateway *cnet.IP
	var err error
	if v3res.Spec.IPv4Gateway != "" {
		ipv4Gateway, _, err = cnet.ParseCIDROrIP(v3res.Spec.IPv4Gateway)
		if err != nil {
			return nil, err
		}
	}

	var ipv6Gateway *cnet.IP
	if v3res.Spec.IPv6Gateway != "" {
		ipv6Gateway, _, err = cnet.ParseCIDROrIP(v3res.Spec.IPv6Gateway)
		if err != nil {
			return nil, err
		}
	}

	var cmac *cnet.MAC
	if v3res.Spec.MAC != "" {
		mac, err := net.ParseMAC(v3res.Spec.MAC)
		if err != nil {
			return nil, err
		}
		cmac = &cnet.MAC{HardwareAddr: mac}
	}

	// Convert the EndpointPort type from the API pkg to the v1 model equivalent type
	ports := []model.EndpointPort{}
	for _, port := range v3res.Spec.Ports {
		// The v1 API doesn't yet support ports which have no name. However, this is allowed on the
		// v3 API and used by the CNI plugin only. Filter these out since Felix doesn't use them anyway.
		if port.Name != "" {
			ports = append(ports, model.EndpointPort{
				Name:     port.Name,
				Protocol: port.Protocol.ToV1(),
				Port:     port.Port,
			})
		}
	}

	// Make sure there are no "namespace" or "serviceaccount" labels on the wep
	// we pass to felix. This prevents a wep from pretending it is
	// in another namespace.
	labels := map[string]string{}
	for k, v := range v3res.GetLabels() {
		if !strings.HasPrefix(k, conversion.NamespaceLabelPrefix) &&
			!strings.HasPrefix(k, conversion.ServiceAccountLabelPrefix) {
			labels[k] = v
		}
	}

	// Add a label for the WEP's serviceaccount if present. We do this in the syncer rather than on the
	// workload endpoint when we create it, because it is possible that a serviceaccount name is longer than
	// the allowable character limit for a label.
	// See https://github.com/projectcalico/calico/issues/4529.
	if v3res.Spec.ServiceAccountName != "" {
		// It's possible that this label is already set, because earlier version of the code set this
		// label on the WorkloadEndpoint directly. If it is, it should be safe to override it
		// with the new spec field since the values will be the same.
		labels[apiv3.LabelServiceAccount] = v3res.Spec.ServiceAccountName
	}

	var allowedSources []cnet.IPNet
	if len(v3res.Spec.AllowSpoofedSourcePrefixes) > 0 {
		for _, prefix := range v3res.Spec.AllowSpoofedSourcePrefixes {
			_, ipn, err := cnet.ParseCIDROrIP(prefix)
			if err != nil {
				return nil, err
			}
			allowedSources = append(allowedSources, *(ipn.Network()))
		}
	}

	v1value := &model.WorkloadEndpoint{
		State:                      "active",
		Name:                       v3res.Spec.InterfaceName,
		Mac:                        cmac,
		ProfileIDs:                 v3res.Spec.Profiles,
		IPv4Nets:                   ipv4Nets,
		IPv6Nets:                   ipv6Nets,
		IPv4NAT:                    ipv4NAT,
		IPv6NAT:                    ipv6NAT,
		Labels:                     labels,
		IPv4Gateway:                ipv4Gateway,
		IPv6Gateway:                ipv6Gateway,
		Ports:                      ports,
		GenerateName:               v3res.GenerateName,
		AllowSpoofedSourcePrefixes: allowedSources,
	}

	return v1value, nil
}

func ConvertV2ToV1IPNAT(ipnat libapiv3.IPNAT) *model.IPNAT {
	internalip := cnet.ParseIP(ipnat.InternalIP)
	externalip := cnet.ParseIP(ipnat.ExternalIP)
	if internalip != nil && externalip != nil {
		return &model.IPNAT{
			IntIP: *internalip,
			ExtIP: *externalip,
		}
	}
	return nil
}
