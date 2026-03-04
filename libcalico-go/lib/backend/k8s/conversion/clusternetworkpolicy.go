// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"sort"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// K8sClusterNetworkPolicyToCalico converts a k8s ClusterNetworkPolicy to a model.KVPair.
func (c converter) K8sClusterNetworkPolicyToCalico(kcnp *clusternetpol.ClusterNetworkPolicy) (*model.KVPair, error) {
	// Pull out important fields.
	tier := clusterNetworkPolicyTier(kcnp)

	order := float64(kcnp.Spec.Priority)
	errorTracker := cerrors.ErrorClusterNetworkPolicyConversion{PolicyName: kcnp.Name}

	// Generate the ingress rules list.
	var ingressRules []apiv3.Rule
	for _, r := range kcnp.Spec.Ingress {
		rules, err := k8sClusterNetPolIngressRuleToCalico(r)
		if err != nil {
			log.WithError(err).Warn("dropping k8s rule that couldn't be converted.")
			// Add rule to conversion error slice
			errorTracker.BadIngressRule(&r, fmt.Sprintf("k8s rule couldn't be converted: %s", err))
			failClosedRule := k8sClusterNetPolHandleFailedRules(r.Action)
			if failClosedRule != nil {
				ingressRules = append(ingressRules, *failClosedRule)
			}
		} else {
			ingressRules = append(ingressRules, rules...)
		}
	}

	// Generate the egress rules list.
	var egressRules []apiv3.Rule
	for _, r := range kcnp.Spec.Egress {
		rules, err := k8sClusterNetPolEgressRuleToCalico(r)
		if err != nil {
			log.WithError(err).Warn("dropping k8s rule that couldn't be converted.")
			// Add rule to conversion error slice
			errorTracker.BadEgressRule(&r, fmt.Sprintf("k8s rule couldn't be converted: %s", err))
			failClosedRule := k8sClusterNetPolHandleFailedRules(r.Action)
			if failClosedRule != nil {
				egressRules = append(egressRules, *failClosedRule)
			}
		} else {
			egressRules = append(egressRules, rules...)
		}
	}

	// Either Namespaces or Pods is set. Use one of them to populate the selectors.
	var nsSelector, podSelector string
	if kcnp.Spec.Subject.Namespaces != nil {
		nsSelector = k8sSelectorToCalico(kcnp.Spec.Subject.Namespaces, SelectorNamespace)
		// Make sure projectcalico.org/orchestrator == 'k8s' label is added to exclude heps.
		podSelector = k8sSelectorToCalico(nil, SelectorPod)
	} else {
		nsSelector = k8sSelectorToCalico(&kcnp.Spec.Subject.Pods.NamespaceSelector, SelectorNamespace)
		podSelector = k8sSelectorToCalico(&kcnp.Spec.Subject.Pods.PodSelector, SelectorPod)
	}

	var uid types.UID
	var err error
	if kcnp.UID != "" {
		uid, err = ConvertUID(kcnp.UID)
		if err != nil {
			return nil, err
		}
	}

	gnp := apiv3.NewGlobalNetworkPolicy()
	gnp.ObjectMeta = metav1.ObjectMeta{
		Name:              kcnp.Name,
		CreationTimestamp: kcnp.CreationTimestamp,
		UID:               uid,
		ResourceVersion:   kcnp.ResourceVersion,
	}
	gnp.Spec = apiv3.GlobalNetworkPolicySpec{
		Tier:              tier,
		Order:             &order,
		NamespaceSelector: nsSelector,
		Selector:          podSelector,
		Ingress:           ingressRules,
		Egress:            egressRules,
		Types:             clusterNetPolicyTypes(ingressRules, egressRules),
	}

	// Build the KVPair.
	kvp := &model.KVPair{
		Key: model.ResourceKey{
			Name: kcnp.Name,
			Kind: model.KindKubernetesClusterNetworkPolicy,
		},
		Value:    gnp,
		Revision: kcnp.ResourceVersion,
	}

	// Return the KVPair with conversion errors if applicable
	return kvp, errorTracker.GetError()
}

func clusterNetPolicyTypes(ingressRules []apiv3.Rule, egressRules []apiv3.Rule) []apiv3.PolicyType {
	// Calculate Types setting. The ANP Tiers are default-Pass so the only
	// reason to enable a policy type is if we have rules.
	var policyTypes []apiv3.PolicyType
	if len(ingressRules) != 0 {
		policyTypes = append(policyTypes, apiv3.PolicyTypeIngress)
	}
	if len(egressRules) != 0 {
		policyTypes = append(policyTypes, apiv3.PolicyTypeEgress)
	}
	return policyTypes
}

func clusterNetworkPolicyTier(kcnp *clusternetpol.ClusterNetworkPolicy) string {
	switch kcnp.Spec.Tier {
	case clusternetpol.AdminTier:
		return names.KubeAdminTierName
	case clusternetpol.BaselineTier:
		return names.KubeBaselineTierName
	default:
		return ""
	}
}

func k8sClusterNetPolHandleFailedRules(action clusternetpol.ClusterNetworkPolicyRuleAction) *apiv3.Rule {
	if action == clusternetpol.ClusterNetworkPolicyRuleActionDeny ||
		action == clusternetpol.ClusterNetworkPolicyRuleActionPass {
		logrus.Warn("replacing failed rule with a deny-all one.")
		return &apiv3.Rule{
			Action: apiv3.Deny,
		}
	}
	return nil
}

func k8sClusterNetPolIngressRuleToCalico(rule clusternetpol.ClusterNetworkPolicyIngressRule) ([]apiv3.Rule, error) {
	action, err := K8sClusterNetworkPolicyActionToCalico(rule.Action)
	if err != nil {
		return nil, err
	}
	return combinePortsWithCNPIngressPeers(rule.Protocols, rule.From, rule.Name, action)
}

func k8sClusterNetPolEgressRuleToCalico(rule clusternetpol.ClusterNetworkPolicyEgressRule) ([]apiv3.Rule, error) {
	action, err := K8sClusterNetworkPolicyActionToCalico(rule.Action)
	if err != nil {
		return nil, err
	}
	return combinePortsWithCNPEgressPeers(rule.Protocols, rule.To, rule.Name, action)
}

func K8sClusterNetworkPolicyActionToCalico(action clusternetpol.ClusterNetworkPolicyRuleAction) (apiv3.Action, error) {
	switch action {
	case clusternetpol.ClusterNetworkPolicyRuleActionAccept:
		return apiv3.Allow, nil
	case clusternetpol.ClusterNetworkPolicyRuleActionDeny,
		clusternetpol.ClusterNetworkPolicyRuleActionPass:
		return apiv3.Action(action), nil
	default:
		return "", fmt.Errorf("unsupported cluster network policy action %v", action)
	}
}

func combinePortsWithCNPIngressPeers(
	cnpProtocols []clusternetpol.ClusterNetworkPolicyProtocol,
	cnpPeers []clusternetpol.ClusterNetworkPolicyIngressPeer,
	ruleName string,
	action apiv3.Action,
) (rules []apiv3.Rule, err error) {
	protocolPorts, sortedProtocols, err := unpackCNPProtocols(cnpProtocols)
	if err != nil {
		return nil, err
	}

	// Combine destinations with sources to generate rules. We generate one rule per protocol,
	// with each rule containing all the allowed ports.
	for _, protocolStr := range sortedProtocols {
		calicoPorts := protocolPorts[protocolStr]
		calicoPorts = SimplifyPorts(calicoPorts)

		var protocol *numorstring.Protocol
		if protocolStr != "" {
			p := numorstring.ProtocolFromString(protocolStr)
			protocol = &p
		}

		// Based on specifications at least one Peer is set.
		var selector, nsSelector string
		for _, peer := range cnpPeers {
			var found bool
			if peer.Namespaces != nil {
				selector = ""
				nsSelector = k8sSelectorToCalico(peer.Namespaces, SelectorNamespace)
				found = true
			}
			if peer.Pods != nil {
				selector = k8sSelectorToCalico(&peer.Pods.PodSelector, SelectorPod)
				nsSelector = k8sSelectorToCalico(&peer.Pods.NamespaceSelector, SelectorNamespace)
				found = true
			}
			if !found {
				return nil, fmt.Errorf("none of supported fields in 'From' is set.")
			}

			// Build inbound rule and append to list.
			rules = append(rules, apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata(ruleName),
				Action:   action,
				Protocol: protocol,
				Source: apiv3.EntityRule{
					Selector:          selector,
					NamespaceSelector: nsSelector,
				},
				Destination: apiv3.EntityRule{
					Ports: calicoPorts,
				},
			})
		}
	}
	return rules, nil
}

func combinePortsWithCNPEgressPeers(
	cnpProtocols []clusternetpol.ClusterNetworkPolicyProtocol,
	cnpPeers []clusternetpol.ClusterNetworkPolicyEgressPeer,
	ruleName string,
	action apiv3.Action,
) (rules []apiv3.Rule, err error) {
	protocolPorts, sortedProtocols, err := unpackCNPProtocols(cnpProtocols)
	if err != nil {
		return nil, err
	}

	// Combine destinations with sources to generate rules. We generate one rule per protocol,
	// with each rule containing all the allowed ports.
	for _, protocolStr := range sortedProtocols {
		calicoPorts := protocolPorts[protocolStr]
		calicoPorts = SimplifyPorts(calicoPorts)

		var protocol *numorstring.Protocol
		if protocolStr != "" {
			p := numorstring.ProtocolFromString(protocolStr)
			protocol = &p
		}

		// Based on specifications at least one Peer is set.
		for _, peer := range cnpPeers {
			var selector, nsSelector string
			var nets []string
			// One and only one of the following fields is set (based on specification).
			var found bool
			if peer.Namespaces != nil {
				nsSelector = k8sSelectorToCalico(peer.Namespaces, SelectorNamespace)
				found = true
			}
			if peer.Pods != nil {
				selector = k8sSelectorToCalico(&peer.Pods.PodSelector, SelectorPod)
				nsSelector = k8sSelectorToCalico(&peer.Pods.NamespaceSelector, SelectorNamespace)
				found = true
			}
			if len(peer.Networks) != 0 {
				for _, n := range peer.Networks {
					_, ipNet, err := cnet.ParseCIDR(string(n))
					if err != nil {
						return nil, fmt.Errorf("invalid CIDR in ANP rule: %w", err)
					}
					nets = append(nets, ipNet.String())
				}
				found = true
			}
			if !found {
				return nil, fmt.Errorf("none of supported fields in 'To' is set.")
			}

			// Build outbound rule and append to list.
			rules = append(rules, apiv3.Rule{
				Metadata: k8sClusterNetworkPolicyToCalicoMetadata(ruleName),
				Action:   action,
				Protocol: protocol,
				Destination: apiv3.EntityRule{
					Ports:             calicoPorts,
					Selector:          selector,
					NamespaceSelector: nsSelector,
					Nets:              nets,
				},
			})
		}
	}

	return rules, nil
}

func unpackCNPProtocols(cnpProtocols []clusternetpol.ClusterNetworkPolicyProtocol) (
	map[string][]numorstring.Port,
	[]string, error,
) {
	// If there are no ports, represent that as zero struct.
	protocols := []clusternetpol.ClusterNetworkPolicyProtocol{{}}
	if cnpProtocols != nil && len(cnpProtocols) != 0 {
		protocols = cnpProtocols
	}

	protocolPorts := map[string][]numorstring.Port{}

	for _, p := range protocols {
		protocol, calicoPort, err := k8sCNPPortToCalicoFields(&p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse k8s protocol: %s", err)
		}

		if protocol == nil && calicoPort == nil {
			// If nil, no ports were specified, or an empty port struct was provided, which we translate to allowing all.
			// We want to use a nil protocol and a nil list of ports, which will allow any destination (for ingress).
			// Given we're gonna allow all, we may as well break here and keep only this rule
			protocolPorts = map[string][]numorstring.Port{"": nil}
			break
		}

		pStr := protocol.String()
		// treat nil as 'all ports'
		if calicoPort == nil {
			protocolPorts[pStr] = nil
		} else if _, ok := protocolPorts[pStr]; !ok || len(protocolPorts[pStr]) > 0 {
			// don't overwrite a nil (allow all ports) if present; if no ports yet for this protocol
			// or 1+ ports which aren't 'all ports', then add the present ports
			protocolPorts[pStr] = append(protocolPorts[pStr], *calicoPort)
		}
	}

	protos := make([]string, 0, len(protocolPorts))
	for p := range protocolPorts {
		protos = append(protos, p)
	}
	// Ensure deterministic output
	sort.Strings(protos)
	return protocolPorts, protos, nil
}

func k8sCNPPortToCalicoFields(cnpProto *clusternetpol.ClusterNetworkPolicyProtocol) (
	protocol *numorstring.Protocol,
	dstPort *numorstring.Port,
	err error,
) {
	// If no port info, return zero values for all fields (protocol, dstPorts).
	if cnpProto == nil {
		return
	}

	if cnpProto.TCP != nil {
		dstPort, err = k8sCNPPortToCalico(cnpProto.TCP.DestinationPort)
		p := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		protocol = &p
		return
	}

	if cnpProto.UDP != nil {
		dstPort, err = k8sCNPPortToCalico(cnpProto.UDP.DestinationPort)
		p := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
		protocol = &p
		return
	}

	if cnpProto.SCTP != nil {
		dstPort, err = k8sCNPPortToCalico(cnpProto.SCTP.DestinationPort)
		p := numorstring.ProtocolFromString(numorstring.ProtocolSCTP)
		protocol = &p
		return
	}

	// TODO: Add support for NamedPorts
	if len(cnpProto.DestinationNamedPort) != 0 {
		err = fmt.Errorf("named ports are not supported yet.")
		return
	}

	return
}

func k8sCNPPortToCalico(port *clusternetpol.Port) (*numorstring.Port, error) {
	// Only one of the Number or Range is set.
	if port == nil {
		return nil, nil
	}
	if port.Number != 0 {
		p := numorstring.SinglePort(uint16(port.Number))
		return &p, nil
	}
	if port.Range != nil {
		p, err := numorstring.PortFromRange(uint16(port.Range.Start), uint16(port.Range.End))
		if err != nil {
			return nil, err
		}
		return &p, nil
	}
	return nil, nil
}

func k8sClusterNetworkPolicyToCalicoMetadata(ruleName string) *apiv3.RuleMetadata {
	if ruleName == "" {
		return nil
	}
	return &apiv3.RuleMetadata{
		Annotations: map[string]string{
			K8sCNPRuleNameLabel: ruleName,
		},
	}
}
