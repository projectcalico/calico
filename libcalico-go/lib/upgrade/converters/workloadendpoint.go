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

package converters

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1 "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

type WorkloadEndpoint struct{}

// APIV1ToBackendV1 converts v1 WorkloadEndpoint API to v1 WorkloadEndpoint KVPair.
func (_ WorkloadEndpoint) APIV1ToBackendV1(rIn unversioned.Resource) (*model.KVPair, error) {
	ah := rIn.(*apiv1.WorkloadEndpoint)
	k, err := convertMetadataToKey(ah.Metadata)
	if err != nil {
		return nil, err
	}

	// IP networks are stored in the datastore in separate IPv4 and IPv6
	// fields.  We normalise the network to ensure the IP is correctly
	// masked.
	ipv4Nets := []net.IPNet{}
	ipv6Nets := []net.IPNet{}
	for _, n := range ah.Spec.IPNetworks {
		n = *(n.Network())
		if n.Version() == 4 {
			ipv4Nets = append(ipv4Nets, n)
		} else {
			ipv6Nets = append(ipv6Nets, n)
		}
	}

	ipv4NAT := []model.IPNAT{}
	ipv6NAT := []model.IPNAT{}
	for _, n := range ah.Spec.IPNATs {
		nat := model.IPNAT{IntIP: n.InternalIP, ExtIP: n.ExternalIP}
		if n.InternalIP.Version() == 4 {
			ipv4NAT = append(ipv4NAT, nat)
		} else {
			ipv6NAT = append(ipv6NAT, nat)
		}
	}

	var ports []model.EndpointPort
	for _, port := range ah.Spec.Ports {
		ports = append(ports, model.EndpointPort{
			Name:     port.Name,
			Protocol: port.Protocol,
			Port:     port.Port,
		})
	}

	var allowedSources []net.IPNet
	for _, prefix := range ah.Spec.AllowSpoofedSourcePrefixes {
		allowedSources = append(allowedSources, prefix)
	}

	d := model.KVPair{
		Key: k,
		Value: &model.WorkloadEndpoint{
			Labels:                     ah.Metadata.Labels,
			ActiveInstanceID:           ah.Metadata.ActiveInstanceID,
			State:                      "active",
			Name:                       ah.Spec.InterfaceName,
			Mac:                        ah.Spec.MAC,
			ProfileIDs:                 ah.Spec.Profiles,
			IPv4Nets:                   ipv4Nets,
			IPv6Nets:                   ipv6Nets,
			IPv4NAT:                    ipv4NAT,
			IPv6NAT:                    ipv6NAT,
			IPv4Gateway:                ah.Spec.IPv4Gateway,
			IPv6Gateway:                ah.Spec.IPv6Gateway,
			Ports:                      ports,
			AllowSpoofedSourcePrefixes: allowedSources,
		},
		Revision: ah.Metadata.Revision,
	}

	log.Debugf("Converted: %+v\n To: %+v", ah, d)

	return &d, nil
}

// BackendV1ToAPIV3 converts v1 WorkloadEndpoint KVPair to v3 API.
func (_ WorkloadEndpoint) BackendV1ToAPIV3(kvp *model.KVPair) (Resource, error) {
	wepKey, ok := kvp.Key.(model.WorkloadEndpointKey)
	if !ok {
		return nil, fmt.Errorf("value is not a valid WorkloadEndpoint resource key")
	}
	wepValue, ok := kvp.Value.(*model.WorkloadEndpoint)
	if !ok {
		return nil, fmt.Errorf("value is not a valid WorkloadEndpoint resource Value")
	}

	labels := convertLabels(wepValue.Labels)
	namespace := "default"

	var err error
	var pod string
	var container string
	var workload string

	// Populate our values based on the orchestrator.
	switch wepKey.OrchestratorID {
	case "k8s":
		if namespace, pod, err = getPodNamespaceName(wepKey.WorkloadID); err != nil {
			return nil, err
		}
		container = wepValue.ActiveInstanceID
	case "cni":
		container = wepKey.WorkloadID
	case "libnetwork":
		workload = "libnetwork"
	default:
		workload = convertName(wepKey.WorkloadID)
	}

	ipNets := convertIPNetworks(wepValue.IPv4Nets)
	ipNets = append(ipNets, convertIPNetworks(wepValue.IPv6Nets)...)

	ipNats := convertIPNATs(wepValue.IPv4NAT)
	ipNats = append(ipNats, convertIPNATs(wepValue.IPv6NAT)...)

	allowedSources := convertIPNetworks(wepValue.AllowSpoofedSourcePrefixes)

	wep := libapiv3.NewWorkloadEndpoint()

	wep.ObjectMeta = v1.ObjectMeta{
		Namespace: namespace,
		Labels:    labels,
	}
	wep.Spec = libapiv3.WorkloadEndpointSpec{
		Orchestrator:               convertName(wepKey.OrchestratorID),
		Workload:                   workload,
		Node:                       ConvertNodeName(wepKey.Hostname),
		Pod:                        pod,
		ContainerID:                container,
		Endpoint:                   convertName(wepKey.EndpointID),
		IPNetworks:                 ipNets,
		IPNATs:                     ipNats,
		Profiles:                   convertProfiles(wepValue.ProfileIDs),
		InterfaceName:              wepValue.Name,
		Ports:                      convertPorts(wepValue.Ports),
		AllowSpoofedSourcePrefixes: allowedSources,
	}

	if wepValue.IPv4Gateway != nil {
		wep.Spec.IPv4Gateway = wepValue.IPv4Gateway.String()
	}
	if wepValue.IPv6Gateway != nil {
		wep.Spec.IPv6Gateway = wepValue.IPv6Gateway.String()
	}
	if wepValue.Mac != nil {
		wep.Spec.MAC = wepValue.Mac.String()
	}

	// Figure out the new name based on WEP fields.
	wepids := names.WorkloadEndpointIdentifiers{
		Node:         wep.Spec.Node,
		Orchestrator: wep.Spec.Orchestrator,
		Endpoint:     wep.Spec.Endpoint,
		Workload:     wep.Spec.Workload,
		Pod:          wep.Spec.Pod,
		ContainerID:  wep.Spec.ContainerID,
	}

	name, err := wepids.CalculateWorkloadEndpointName(false)
	if err != nil {
		return nil, err
	}
	wep.ObjectMeta.Name = name

	log.Debugf("Converted: %+v\n To: %+v", kvp, wep)

	return wep, nil
}

func convertMetadataToKey(m unversioned.ResourceMetadata) (model.Key, error) {
	hm := m.(apiv1.WorkloadEndpointMetadata)
	k := model.WorkloadEndpointKey{
		Hostname:       hm.Node,
		OrchestratorID: hm.Orchestrator,
		WorkloadID:     hm.Workload,
		EndpointID:     hm.Name,
	}
	return k, nil
}

// convertLabels creates a new map of labels, and updates the v1 namespace label to the v3 style.
func convertLabels(v1Labels map[string]string) map[string]string {
	labels := map[string]string{}
	for k, v := range v1Labels {
		labels[k] = v
	}

	if val, ok := labels["calico/k8s_ns"]; ok {
		labels["projectcalico.org/namespace"] = val
		delete(labels, "calico/k8s_ns")
	}

	return labels
}

// convertIPNetworks updates the old []net.IPNet to []string.
func convertIPNetworks(ipNetworks []net.IPNet) []string {
	var ipNets []string
	for _, ipNet := range ipNetworks {
		ipNets = append(ipNets, ipNet.String())
	}

	return ipNets
}

// convertIPNATs updates the type of IPNAT struct used.
func convertIPNATs(v1IPNATs []model.IPNAT) []libapiv3.IPNAT {
	var ipNATs []libapiv3.IPNAT
	for _, ipNAT := range v1IPNATs {
		ipNATs = append(ipNATs, libapiv3.IPNAT{
			InternalIP: ipNAT.IntIP.String(),
			ExternalIP: ipNAT.ExtIP.String(),
		})
	}

	return ipNATs
}

// convertProfiles updates the Kubernetes namespace portion from "k8s_ns" to "kns" for each profile.
func convertProfiles(v1Profiles []string) []string {
	var v3Profiles []string
	for _, p := range v1Profiles {
		v3Profiles = append(v3Profiles, convertProfileName(p))
	}

	return v3Profiles
}

// getPodNamespaceName separates the workload string which is in the format "namespace.podName" into
// both parts and returns both the namespace and pod name.
func getPodNamespaceName(workload string) (string, string, error) {
	parts := strings.SplitN(workload, ".", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed k8s workload ID '%s': workload was not added "+
			"through the Calico CNI plugin and cannot be converted", workload)
	}
	return parts[0], parts[1], nil
}

// convertPorts updates to the new libapiv3.WorkloadEndpointPort struct.
func convertPorts(v1Ports []model.EndpointPort) []libapiv3.WorkloadEndpointPort {
	var v3Ports []libapiv3.WorkloadEndpointPort
	for _, p := range v1Ports {
		v3Ports = append(v3Ports, libapiv3.WorkloadEndpointPort{
			Name:     p.Name,
			Protocol: p.Protocol,
			Port:     p.Port,
		})
	}

	return v3Ports
}
