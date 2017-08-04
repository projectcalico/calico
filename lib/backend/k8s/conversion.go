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

package k8s

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	kapiv1 "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"

	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

var (
	protoTCP = kapiv1.ProtocolTCP
)

type converter struct {
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

// parseWorkloadID extracts the Namespace and Pod name from the given workload ID.
func (c converter) parseWorkloadID(workloadID string) (string, string) {
	splits := strings.SplitN(workloadID, ".", 2)
	return splits[0], splits[1]
}

// parsePolicyNameNamespace extracts the Kubernetes Namespace that backs the given Policy.
func (c converter) parsePolicyNameNamespace(name string) (string, error) {
	// Policy objects backed by Namespaces have form "ns.projectcalico.org/<ns_name>"
	if !strings.HasPrefix(name, "ns.projectcalico.org/") {
		// This is not backed by a Kubernetes Namespace.
		return "", fmt.Errorf("Policy %s not backed by a Namespace", name)
	}

	return strings.TrimPrefix(name, "ns.projectcalico.org/"), nil
}

// parsePolicyNameNetworkPolicy extracts the Kubernetes Namespace and NetworkPolicy that backs the given Policy.
func (c converter) parsePolicyNameNetworkPolicy(name string) (string, string, error) {
	// Policies backed by NetworkPolicies have form "np.projectcalico.org/<ns_name>.<np_name>"
	if !strings.HasPrefix(name, "np.projectcalico.org/") {
		// This is not backed by a Kubernetes NetworkPolicy.
		return "", "", fmt.Errorf("Policy %s not backed by a NetworkPolicy", name)
	}

	splits := strings.SplitN(strings.TrimPrefix(name, "np.projectcalico.org/"), ".", 2)
	if len(splits) != 2 {
		return "", "", fmt.Errorf("Name does not include both Namespace and NetworkPolicy: %s", name)
	}
	// Return Namespace, NetworkPolicy name.
	return splits[0], splits[1], nil
}

// parseProfileName extracts the Namespace name from the given Profile name.
func (c converter) parseProfileName(profileName string) (string, error) {
	// Profile objects backed by Namespaces have form "ns.projectcalico.org/<ns_name>"
	if !strings.HasPrefix(profileName, "ns.projectcalico.org/") {
		// This is not backed by a Kubernetes Namespace.
		return "", fmt.Errorf("Profile %s not backed by a Namespace", profileName)
	}

	return strings.TrimPrefix(profileName, "ns.projectcalico.org/"), nil
}

// namespaceToProfile converts a Namespace to a Calico Profile.  The Profile stores
// labels from the Namespace which are inherited by the WorkloadEndpoints within
// the Profile. This Profile also has the default ingress and egress rules, which are both 'allow'.
func (c converter) namespaceToProfile(ns *kapiv1.Namespace) (*model.KVPair, error) {
	// Generate the labels to apply to the profile, using a special prefix
	// to indicate that these are the labels from the parent Kubernetes Namespace.
	labels := map[string]string{}
	for k, v := range ns.ObjectMeta.Labels {
		labels[fmt.Sprintf("k8s_ns/label/%s", k)] = v
	}

	name := fmt.Sprintf("ns.projectcalico.org/%s", ns.ObjectMeta.Name)
	kvp := model.KVPair{
		Key: model.ProfileKey{Name: name},
		Value: &model.Profile{
			Labels: labels,
			Rules: model.ProfileRules{
				InboundRules:  []model.Rule{model.Rule{Action: "allow"}},
				OutboundRules: []model.Rule{model.Rule{Action: "allow"}},
			},
		},
		Revision: ns.ObjectMeta.ResourceVersion,
	}
	return &kvp, nil
}

// isReadyCalicoPod returns true if the pod should be shown as a workloadEndpoint
// in the Calico API and false otherwise.
func (c converter) isReadyCalicoPod(pod *kapiv1.Pod) bool {
	if c.isHostNetworked(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is host networked.")
		return false
	} else if !c.hasIPAddress(pod) {
		log.WithField("pod", pod.Name).Debug("Pod does not have an IP address.")
		return false
	} else if !c.isScheduled(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is not scheduled.")
		return false
	}
	return true
}

func (c converter) isScheduled(pod *kapiv1.Pod) bool {
	return pod.Spec.NodeName != ""
}

func (c converter) isHostNetworked(pod *kapiv1.Pod) bool {
	return pod.Spec.HostNetwork
}

func (c converter) hasIPAddress(pod *kapiv1.Pod) bool {
	return pod.Status.PodIP != ""
}

// podToWorkloadEndpoint converts a Pod to a WorkloadEndpoint.  It assumes the calling code
// has verified that the provided Pod is valid to convert to a WorkloadEndpoint.
func (c converter) podToWorkloadEndpoint(pod *kapiv1.Pod) (*model.KVPair, error) {
	// Pull out the profile and workload ID based on pod name and Namespace.
	profile := fmt.Sprintf("ns.projectcalico.org/%s", pod.ObjectMeta.Namespace)
	workload := fmt.Sprintf("%s.%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)

	// We do, in some circumstances, want to parse Pods without an IP address.  For example,
	// a DELETE update will not include an IP.
	ipNets := []cnet.IPNet{}
	if c.hasIPAddress(pod) {
		_, ipNet, err := cnet.ParseCIDR(fmt.Sprintf("%s/32", pod.Status.PodIP))
		if err != nil {
			log.WithFields(log.Fields{"ip": pod.Status.PodIP, "pod": pod.Name}).WithError(err).Error("Failed to parse pod IP")
			return nil, err
		}
		ipNets = append(ipNets, *ipNet)
	}

	// Generate the interface name and MAC based on workload.  This must match
	// the host-side veth configured by the CNI plugin.
	interfaceName := VethNameForWorkload(workload)

	// Build the labels map.
	labels := map[string]string{}
	if pod.ObjectMeta.Labels != nil {
		labels = pod.ObjectMeta.Labels
	}
	labels["calico/k8s_ns"] = pod.ObjectMeta.Namespace

	// Create the key / value pair to return.
	kvp := model.KVPair{
		Key: model.WorkloadEndpointKey{
			Hostname:       pod.Spec.NodeName,
			OrchestratorID: "k8s",
			WorkloadID:     workload,
			EndpointID:     "eth0",
		},
		Value: &model.WorkloadEndpoint{
			State:      "active",
			Name:       interfaceName,
			ProfileIDs: []string{profile},
			IPv4Nets:   ipNets,
			IPv6Nets:   []cnet.IPNet{},
			Labels:     labels,
		},
		Revision: pod.ObjectMeta.ResourceVersion,
	}
	return &kvp, nil
}

// networkPolicyToPolicy converts a k8s NetworkPolicy to a model.KVPair.
func (c converter) networkPolicyToPolicy(np *extensions.NetworkPolicy) (*model.KVPair, error) {
	// Pull out important fields.
	policyName := fmt.Sprintf("np.projectcalico.org/%s.%s", np.ObjectMeta.Namespace, np.ObjectMeta.Name)

	// We insert all the NetworkPolicy Policies at order 1000.0 after conversion.
	// This order might change in future.
	order := float64(1000.0)

	// Generate the inbound rules list.
	inboundRules := []model.Rule{}
	for _, r := range np.Spec.Ingress {
		inboundRules = append(inboundRules, c.k8sIngressRuleToCalico(r, np.ObjectMeta.Namespace)...)
	}

	// Build and return the KVPair.
	return &model.KVPair{
		Key: model.PolicyKey{
			Name: policyName,
		},
		Value: &model.Policy{
			Order:         &order,
			Selector:      c.k8sSelectorToCalico(&np.Spec.PodSelector, &np.ObjectMeta.Namespace),
			InboundRules:  inboundRules,
			OutboundRules: []model.Rule{model.Rule{Action: "allow"}},
		},
		Revision: np.ObjectMeta.ResourceVersion,
	}, nil
}

// k8sSelectorToCalico takes a namespaced k8s label selector and returns the Calico
// equivalent.
func (c converter) k8sSelectorToCalico(s *metav1.LabelSelector, ns *string) string {
	// If this is a podSelector, it needs to be namespaced, and it
	// uses a different prefix.  Otherwise, treat this as a NamespaceSelector.
	selectors := []string{}
	prefix := "k8s_ns/label/"
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

func (c converter) k8sIngressRuleToCalico(r extensions.NetworkPolicyIngressRule, ns string) []model.Rule {
	rules := []model.Rule{}
	peers := []*extensions.NetworkPolicyPeer{}
	ports := []*extensions.NetworkPolicyPort{}

	// Built up a list of the sources and a list of the destinations.
	for _, f := range r.From {
		// We need to add a copy of the peer so all the rules don't
		// point to the same location.
		peers = append(peers, &extensions.NetworkPolicyPeer{
			NamespaceSelector: f.NamespaceSelector,
			PodSelector:       f.PodSelector,
		})
	}
	for _, p := range r.Ports {
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

	// Combine desintations with sources to generate rules.
	// TODO: This currently creates a lot of rules by making every combination of from / ports
	// into a rule.  We can combine these so that we don't need as many rules!
	for _, port := range ports {
		for _, peer := range peers {
			// Build rule and append to list.
			rules = append(rules, c.buildRule(port, peer, ns))
		}
	}
	return rules
}

func (c converter) buildRule(port *extensions.NetworkPolicyPort, peer *extensions.NetworkPolicyPeer, ns string) model.Rule {
	var protocol *numorstring.Protocol
	dstPorts := []numorstring.Port{}
	srcSelector := ""
	if port != nil {
		// Port information available.
		protocol = c.k8sProtocolToCalico(port.Protocol)
		dstPorts = c.k8sPortToCalico(*port)
	}
	if peer != nil {
		// Peer information available.
		srcSelector = c.k8sPeerToCalicoSelector(*peer, ns)
	}

	// Build the rule.
	return model.Rule{
		Action:      "allow",
		Protocol:    protocol,
		SrcSelector: srcSelector,
		DstPorts:    dstPorts,
	}
}

func (c converter) k8sProtocolToCalico(protocol *kapiv1.Protocol) *numorstring.Protocol {
	if protocol != nil {
		p := numorstring.ProtocolFromString(strings.ToLower(string(*protocol)))
		return &p
	}
	return nil
}

func (c converter) k8sPeerToCalicoSelector(peer extensions.NetworkPolicyPeer, ns string) string {
	// Determine the source selector for the rule.
	// Only one of PodSelector / NamespaceSelector can be defined.
	if peer.PodSelector != nil {
		return c.k8sSelectorToCalico(peer.PodSelector, &ns)
	}
	if peer.NamespaceSelector != nil {
		return c.k8sSelectorToCalico(peer.NamespaceSelector, nil)
	}

	// Neither is defined - return an empty selector.
	return ""
}

func (c converter) k8sPortToCalico(port extensions.NetworkPolicyPort) []numorstring.Port {
	if port.Port != nil {
		p, err := numorstring.PortFromString(port.Port.String())
		if err != nil {
			log.Panic("Invalid port %+v: %s", port.Port, err)
		}
		return []numorstring.Port{p}
	}

	// No ports - return empty list.
	return []numorstring.Port{}
}
