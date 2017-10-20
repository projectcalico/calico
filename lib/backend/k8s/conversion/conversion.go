// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package conversion

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var (
	protoTCP = kapiv1.ProtocolTCP
)

//TODO: make this private and expose a public conversion interface instead
type Converter struct {
}

// VethNameForWorkload returns a deterministic veth name
// for the given Kubernetes workload.
func VethNameForWorkload(workload string) string {
	// A SHA1 is always 20 bytes long, and so is sufficient for generating the
	// veth name and mac addr.
	h := sha1.New()
	h.Write([]byte(workload))
	return fmt.Sprintf("cali%s", hex.EncodeToString(h.Sum(nil))[:11])
}

// ParseWorkloadName extracts the Node name, Orchestrator, Pod name and endpoint from the
// given WorkloadEndpoint name.
// The expected format for k8s is <node>-k8s-<pod>-<endpoint>
func (c Converter) ParseWorkloadEndpointName(workloadName string) (names.WorkloadEndpointIdentifiers, error) {
	return names.ParseWorkloadEndpointName(workloadName)
}

// ParsePolicyNameNetworkPolicy extracts the Kubernetes Namespace and NetworkPolicy that backs the given Policy.
func (c Converter) ParsePolicyNameNetworkPolicy(name string) (string, string, error) {
	// Policies backed by NetworkPolicies have form "knp.default.<ns_name>.<np_name>"
	if !strings.HasPrefix(name, "knp.default.") {
		// This is not backed by a Kubernetes NetworkPolicy.
		return "", "", fmt.Errorf("Policy %s not backed by a NetworkPolicy", name)
	}

	splits := strings.SplitN(strings.TrimPrefix(name, "knp.default."), ".", 2)
	if len(splits) != 2 {
		return "", "", fmt.Errorf("Name does not include both Namespace and NetworkPolicy: %s", name)
	}
	// Return Namespace, NetworkPolicy name.
	return splits[0], splits[1], nil
}

// NamespaceToProfile converts a Namespace to a Calico Profile.  The Profile stores
// labels from the Namespace which are inherited by the WorkloadEndpoints within
// the Profile. This Profile also has the default ingress and egress rules, which are both 'allow'.
func (c Converter) NamespaceToProfile(ns *kapiv1.Namespace) (*model.KVPair, error) {
	// Generate the labels to apply to the profile, using a special prefix
	// to indicate that these are the labels from the parent Kubernetes Namespace.
	labels := map[string]string{}
	for k, v := range ns.ObjectMeta.Labels {
		labels[fmt.Sprintf("pcns.%s", k)] = v
	}

	name := fmt.Sprintf("k8s_ns.%s", ns.ObjectMeta.Name)
	kvp := model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: apiv2.KindProfile,
		},
		Value: &apiv2.Profile{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				Labels:            labels,
				CreationTimestamp: ns.CreationTimestamp,
				UID:               ns.UID,
			},
			Spec: apiv2.ProfileSpec{
				IngressRules: []apiv2.Rule{apiv2.Rule{Action: apiv2.Allow}},
				EgressRules:  []apiv2.Rule{apiv2.Rule{Action: apiv2.Allow}},
			},
		},
		Revision: ns.ObjectMeta.ResourceVersion,
	}
	return &kvp, nil
}

// IsReadyCalicoPod returns true if the pod should be shown as a workloadEndpoint
// in the Calico API and false otherwise.
func (c Converter) IsReadyCalicoPod(pod *kapiv1.Pod) bool {
	if c.IsHostNetworked(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is host networked.")
		return false
	} else if !c.HasIPAddress(pod) {
		log.WithField("pod", pod.Name).Debug("Pod does not have an IP address.")
		return false
	} else if !c.IsScheduled(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is not scheduled.")
		return false
	}
	return true
}

func (c Converter) IsScheduled(pod *kapiv1.Pod) bool {
	return pod.Spec.NodeName != ""
}

func (c Converter) IsHostNetworked(pod *kapiv1.Pod) bool {
	return pod.Spec.HostNetwork
}

func (c Converter) HasIPAddress(pod *kapiv1.Pod) bool {
	return pod.Status.PodIP != ""
}

// PodToWorkloadEndpoint converts a Pod to a WorkloadEndpoint.  It assumes the calling code
// has verified that the provided Pod is valid to convert to a WorkloadEndpoint.
// PodToWorkloadEndpoint requires a Pods Name and Node Name to be populated. It will
// fail to convert from a Pod to WorkloadEndpoint otherwise.
func (c Converter) PodToWorkloadEndpoint(pod *kapiv1.Pod) (*model.KVPair, error) {
	// Pull out the profile and workload ID based on pod name and Namespace.
	profile := fmt.Sprintf("k8s_ns.%s", pod.ObjectMeta.Namespace)
	wepids := names.WorkloadEndpointIdentifiers{
		Node:         pod.Spec.NodeName,
		Orchestrator: "k8s",
		Endpoint:     "eth0",
		Pod:          pod.ObjectMeta.Name,
	}
	wepName, err := wepids.CalculateWorkloadEndpointName(false)
	if err != nil {
		return nil, err
	}

	// We do, in some circumstances, want to parse Pods without an IP address.  For example,
	// a DELETE update will not include an IP.
	ipNets := []string{}
	if c.HasIPAddress(pod) {
		_, ipNet, err := cnet.ParseCIDROrIP(pod.Status.PodIP)
		if err != nil {
			log.WithFields(log.Fields{"ip": pod.Status.PodIP, "pod": pod.Name}).WithError(err).Error("Failed to parse pod IP")
			return nil, err
		}
		ipNets = append(ipNets, ipNet.String())
	}

	// Generate the interface name based on workload.  This must match
	// the host-side veth configured by the CNI plugin.
	interfaceName := VethNameForWorkload(wepName)

	// Build the labels map.
	labels := map[string]string{}
	if pod.ObjectMeta.Labels != nil {
		labels = pod.ObjectMeta.Labels
	}
	labels["calico/k8s_ns"] = pod.ObjectMeta.Namespace

	// Map any named ports through.
	var endpointPorts []apiv2.EndpointPort
	for _, container := range pod.Spec.Containers {
		for _, containerPort := range container.Ports {
			if containerPort.Name != "" && containerPort.ContainerPort != 0 {
				var modelProto numorstring.Protocol
				switch containerPort.Protocol {
				case kapiv1.ProtocolUDP:
					modelProto = numorstring.ProtocolFromString("udp")
				case kapiv1.ProtocolTCP, kapiv1.Protocol("") /* K8s default is TCP. */ :
					modelProto = numorstring.ProtocolFromString("tcp")
				default:
					log.WithFields(log.Fields{
						"protocol": containerPort.Protocol,
						"pod":      pod,
						"port":     containerPort,
					}).Debug("Ignoring named port with unknown protocol")
					continue
				}

				endpointPorts = append(endpointPorts, apiv2.EndpointPort{
					Name:     containerPort.Name,
					Protocol: modelProto,
					Port:     uint16(containerPort.ContainerPort),
				})
			}
		}
	}

	// Create the key / value pair to return.
	kvp := model.KVPair{
		Key: model.ResourceKey{
			Name:      wepName,
			Namespace: pod.ObjectMeta.Namespace,
			Kind:      apiv2.KindWorkloadEndpoint,
		},
		Value: &apiv2.WorkloadEndpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wepName,
				Namespace: pod.ObjectMeta.Namespace,
				Labels:    labels,
			},
			Spec: apiv2.WorkloadEndpointSpec{
				Orchestrator:  "k8s",
				Node:          pod.Spec.NodeName,
				Pod:           pod.Name,
				Endpoint:      "eth0",
				InterfaceName: interfaceName,
				Profiles:      []string{profile},
				IPNetworks:    ipNets,
				Ports:         endpointPorts,
			},
		},
		Revision: pod.ObjectMeta.ResourceVersion,
	}
	return &kvp, nil
}

// K8sNetworkPolicyToCalico converts a k8s NetworkPolicy to a model.KVPair.
func (c Converter) K8sNetworkPolicyToCalico(np *extensions.NetworkPolicy) (*model.KVPair, error) {
	// Pull out important fields.
	policyName := fmt.Sprintf("knp.default.%s.%s", np.ObjectMeta.Namespace, np.ObjectMeta.Name)

	// We insert all the NetworkPolicy Policies at order 1000.0 after conversion.
	// This order might change in future.
	order := float64(1000.0)

	// Generate the ingress rules list.
	var ingressRules []apiv2.Rule
	for _, r := range np.Spec.Ingress {
		ingressRules = append(ingressRules, c.k8sRuleToCalico(r.From, r.Ports, np.ObjectMeta.Namespace, true)...)
	}

	// Generate the egress rules list.
	var egressRules []apiv2.Rule
	for _, r := range np.Spec.Egress {
		egressRules = append(egressRules, c.k8sRuleToCalico(r.To, r.Ports, np.ObjectMeta.Namespace, false)...)
	}

	// Calculate Types setting.
	ingress := false
	egress := false
	for _, policyType := range np.Spec.PolicyTypes {
		switch policyType {
		case extensions.PolicyTypeIngress:
			ingress = true
		case extensions.PolicyTypeEgress:
			egress = true
		}
	}
	types := []apiv2.PolicyType{}
	if ingress {
		types = append(types, apiv2.PolicyTypeIngress)
	}
	if egress {
		types = append(types, apiv2.PolicyTypeEgress)
	} else if len(egressRules) > 0 {
		// Egress was introduced at the same time as policyTypes.  It shouldn't be possible to
		// receive a NetworkPolicy with an egress rule but without "egress" specified in its types,
		// but we'll warn about it anyway.
		log.Warn("K8s PolicyTypes don't include 'egress', but NetworkPolicy has egress rules.")
	}

	// If no types were specified in the policy, then we're running on a cluster that doesn't
	// include support for that field in the API.  In that case, the correct behavior is for the policy
	// to apply to only ingress traffic.
	if len(types) == 0 {
		types = append(types, apiv2.PolicyTypeIngress)
	}

	// Build and return the KVPair.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name: policyName,
			Kind: apiv2.KindNetworkPolicy,
		},
		Value: &apiv2.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policyName,
				Namespace: np.ObjectMeta.Namespace,
			},
			Spec: apiv2.PolicySpec{
				Order:        &order,
				Selector:     c.k8sSelectorToCalico(&np.Spec.PodSelector, &np.ObjectMeta.Namespace),
				IngressRules: ingressRules,
				EgressRules:  egressRules,
				Types:        types,
			},
		},
		Revision: np.ObjectMeta.ResourceVersion,
	}, nil
}

// k8sSelectorToCalico takes a namespaced k8s label selector and returns the Calico
// equivalent.
func (c Converter) k8sSelectorToCalico(s *metav1.LabelSelector, ns *string) string {
	// If this is a podSelector, it needs to be namespaced, and it
	// uses a different prefix.  Otherwise, treat this as a NamespaceSelector.
	selectors := []string{}
	prefix := "pcns."
	if ns != nil {
		prefix = ""
		selectors = append(selectors, fmt.Sprintf("calico/k8s_ns == '%s'", *ns))
	}

	// matchLabels is a map key => value, it means match if (label[key] ==
	// value) for all keys.
	keys := make([]string, 0, len(s.MatchLabels))
	for k := range s.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := s.MatchLabels[k]
		selectors = append(selectors, fmt.Sprintf("%s%s == '%s'", prefix, k, v))
	}

	// matchExpressions is a list of in/notin/exists/doesnotexist tests.
	for _, e := range s.MatchExpressions {
		valueList := strings.Join(e.Values, "', '")

		// Each selector is formatted differently based on the operator.
		switch e.Operator {
		case metav1.LabelSelectorOpIn:
			selectors = append(selectors, fmt.Sprintf("%s%s in { '%s' }", prefix, e.Key, valueList))
		case metav1.LabelSelectorOpNotIn:
			selectors = append(selectors, fmt.Sprintf("%s%s not in { '%s' }", prefix, e.Key, valueList))
		case metav1.LabelSelectorOpExists:
			selectors = append(selectors, fmt.Sprintf("has(%s%s)", prefix, e.Key))
		case metav1.LabelSelectorOpDoesNotExist:
			selectors = append(selectors, fmt.Sprintf("! has(%s%s)", prefix, e.Key))
		}
	}

	// If namespace selector is empty then we select all namespaces.
	if len(selectors) == 0 && ns == nil {
		selectors = []string{"has(calico/k8s_ns)"}
	}

	return strings.Join(selectors, " && ")
}

func (c Converter) k8sRuleToCalico(rPeers []extensions.NetworkPolicyPeer, rPorts []extensions.NetworkPolicyPort, ns string, ingress bool) []apiv2.Rule {
	rules := []apiv2.Rule{}
	peers := []*extensions.NetworkPolicyPeer{}
	ports := []*extensions.NetworkPolicyPort{}

	// Built up a list of the sources and a list of the destinations.
	for _, f := range rPeers {
		// We need to add a copy of the peer so all the rules don't
		// point to the same location.
		peers = append(peers, &extensions.NetworkPolicyPeer{
			NamespaceSelector: f.NamespaceSelector,
			PodSelector:       f.PodSelector,
			IPBlock:           f.IPBlock,
		})
	}
	for _, p := range rPorts {
		// We need to add a copy of the port so all the rules don't
		// point to the same location.
		port := extensions.NetworkPolicyPort{}
		if p.Port != nil {
			portval := intstr.FromString(p.Port.String())
			port.Port = &portval

			// TCP is the implicit default (as per the definition of NetworkPolicyPort).
			// Make the default explicit here because our data-model always requires
			// the protocol to be specified if we're doing a port match.
			port.Protocol = &protoTCP
		}
		if p.Protocol != nil {
			protval := kapiv1.Protocol(fmt.Sprintf("%s", *p.Protocol))
			port.Protocol = &protval
		}
		ports = append(ports, &port)
	}

	// If there no peers, or no ports, represent that as nil.
	if len(peers) == 0 {
		peers = []*extensions.NetworkPolicyPeer{nil}
	}
	if len(ports) == 0 {
		ports = []*extensions.NetworkPolicyPort{nil}
	}

	// Combine destinations with sources to generate rules.
	// TODO: This currently creates a lot of rules by making every combination of from / ports
	// into a rule.  We can combine these so that we don't need as many rules!
	for _, port := range ports {
		for _, peer := range peers {
			protocol, calicoPorts := c.k8sPortToCalicoFields(port)
			selector, nets, notNets := c.k8sPeerToCalicoFields(peer, ns)
			if ingress {
				// Build inbound rule and append to list.
				rules = append(rules, apiv2.Rule{
					Action:   "allow",
					Protocol: protocol,
					Source: apiv2.EntityRule{
						Selector: selector,
						Nets:     nets,
						NotNets:  notNets,
					},
					Destination: apiv2.EntityRule{
						Ports: calicoPorts,
					},
				})
			} else {
				// Build outbound rule and append to list.
				rules = append(rules, apiv2.Rule{
					Action:   "allow",
					Protocol: protocol,
					Destination: apiv2.EntityRule{
						Ports:    calicoPorts,
						Selector: selector,
						Nets:     nets,
						NotNets:  notNets,
					},
				})
			}
		}
	}
	return rules
}

func (c Converter) k8sPortToCalicoFields(port *extensions.NetworkPolicyPort) (protocol *numorstring.Protocol, dstPorts []numorstring.Port) {
	// If no port info, return zero values for all fields (protocol, dstPorts).
	if port == nil {
		return
	}
	// Port information available.
	protocol = c.k8sProtocolToCalico(port.Protocol)
	dstPorts = c.k8sPortToCalico(*port)
	return
}

func (c Converter) k8sProtocolToCalico(protocol *kapiv1.Protocol) *numorstring.Protocol {
	if protocol != nil {
		p := numorstring.ProtocolFromString(strings.ToLower(string(*protocol)))
		return &p
	}
	return nil
}

func (c Converter) k8sPeerToCalicoFields(peer *extensions.NetworkPolicyPeer, ns string) (selector string, nets []string, notNets []string) {
	// If no peer, return zero values for all fields (selector, nets and !nets).
	if peer == nil {
		return
	}
	// Peer information available.
	// Determine the source selector for the rule.
	// Only one of PodSelector / NamespaceSelector can be defined.
	if peer.PodSelector != nil {
		selector = c.k8sSelectorToCalico(peer.PodSelector, &ns)
		return
	}
	if peer.NamespaceSelector != nil {
		selector = c.k8sSelectorToCalico(peer.NamespaceSelector, nil)
		return
	}
	if peer.IPBlock != nil {
		// Convert the CIDR to include.
		_, ipNet, err := cnet.ParseCIDR(peer.IPBlock.CIDR)
		if err != nil {
			log.WithField("cidr", peer.IPBlock.CIDR).WithError(err).Error("Failed to parse CIDR")
			return
		}
		nets = []string{ipNet.String()}

		// Convert the CIDRs to exclude.
		notNets = []string{}
		for _, exception := range peer.IPBlock.Except {
			_, ipNet, err = cnet.ParseCIDR(exception)
			if err != nil {
				log.WithField("cidr", exception).WithError(err).Error("Failed to parse CIDR")
				return
			}
			notNets = append(notNets, ipNet.String())
		}
		return
	}
	return
}

func (c Converter) k8sPortToCalico(port extensions.NetworkPolicyPort) []numorstring.Port {
	var portList []numorstring.Port
	if port.Port != nil {
		p, err := numorstring.PortFromString(port.Port.String())
		if err != nil {
			log.WithError(err).Panicf("Invalid port %+v", port.Port)
		}
		return append(portList, p)
	}

	// No ports - return empty list.
	return portList
}

// ProfileNameToNamespace extracts the Namespace name from the given Profile name.
func (c Converter) ProfileNameToNamespace(profileName string) (string, error) {
	// Profile objects backed by Namespaces have form "k8s_ns.<ns_name>"
	if !strings.HasPrefix(profileName, "k8s_ns.") {
		// This is not backed by a Kubernetes Namespace.
		return "", fmt.Errorf("Profile %s not backed by a Namespace", profileName)
	}

	return strings.TrimPrefix(profileName, "k8s_ns."), nil
}
