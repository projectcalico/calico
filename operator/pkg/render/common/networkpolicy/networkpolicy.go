// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package networkpolicy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
)

const (
	CalicoTierName                       = "calico-system"
	CalicoComponentPolicyPrefix          = CalicoTierName + "."
	CalicoComponentDefaultDenyPolicyName = CalicoComponentPolicyPrefix + "default-deny"
)

var (
	TCPProtocol               = numorstring.ProtocolFromString(numorstring.ProtocolTCP)
	UDPProtocol               = numorstring.ProtocolFromString(numorstring.ProtocolUDP)
	HighPrecedenceOrder       = 1.0
	AfterHighPrecendenceOrder = 10.0
)

// AppendDNSEgressRules appends a rule to the provided slice that allows DNS egress. The appended rule utilizes label selectors and ports.
func AppendDNSEgressRules(egressRules []v3.Rule, openShift bool) []v3.Rule {
	if openShift {
		egressRules = append(egressRules, []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					NamespaceSelector: "kubernetes.io/metadata.name == 'openshift-dns'",
					Selector:          "dns.operator.openshift.io/daemonset-dns == 'default'",
					Ports:             Ports(5353),
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &TCPProtocol,
				Destination: v3.EntityRule{
					NamespaceSelector: "kubernetes.io/metadata.name == 'openshift-dns'",
					Selector:          "dns.operator.openshift.io/daemonset-dns == 'default'",
					Ports:             Ports(5353),
				},
			},
		}...)
	} else {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &UDPProtocol,
			Destination: v3.EntityRule{
				NamespaceSelector: "kubernetes.io/metadata.name == 'kube-system'",
				// In most Kubernetes distros the label is for kube-dns, but in Canonical it is for coredns.
				Selector: "k8s-app in { 'kube-dns', 'coredns' }",
				Ports:    Ports(53),
			},
		})
	}

	return egressRules
}

// CreateEntityRule creates an entity rule that matches traffic using label selectors based on namespace, deployment name, and port.
func CreateEntityRule(namespace string, deploymentName string, ports ...uint16) v3.EntityRule {
	return v3.EntityRule{
		NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", namespace),
		Selector:          fmt.Sprintf("k8s-app == '%s'", deploymentName),
		Ports:             Ports(ports...),
	}
}

// CreateSourceEntityRule creates a conventional entity rule that matches ingress traffic based on namespace and deployment name.
func CreateSourceEntityRule(namespace string, deploymentName string) v3.EntityRule {
	return v3.EntityRule{
		Selector:          fmt.Sprintf("k8s-app == '%s'", deploymentName),
		NamespaceSelector: fmt.Sprintf("kubernetes.io/metadata.name == '%s'", namespace),
	}
}

// GetOIDCEgressRule creates egress rule for oidc connection.
// the result will include an egress rules with the urlString passed in:
//  1. egress rule: egress rule assuming the oidc is external to the cluster
func GetOIDCEgressRule(parsedURL *url.URL) v3.Rule {
	hostname := parsedURL.Hostname()
	OIDCEntityRuleExternal := v3.EntityRule{
		Domains: []string{hostname},
	}

	return v3.Rule{
		Action:      v3.Allow,
		Protocol:    &TCPProtocol,
		Destination: OIDCEntityRuleExternal,
	}
}

// AppendServiceSelectorDNSEgressRules is equivalent to AppendDNSEgressRules, utilizing service selector instead of label selector and ports.
func AppendServiceSelectorDNSEgressRules(egressRules []v3.Rule, openShift bool) []v3.Rule {
	if openShift {
		egressRules = append(egressRules, []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "default",
						Name:      "openshift-dns",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &TCPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "default",
						Name:      "openshift-dns",
					},
				},
			},
		}...)
	} else {
		// In most Kubernetes distros, the DNS service is kube-dns, but in Canonical it is coredns.
		egressRules = append(egressRules, []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "kube-system",
						Name:      "kube-dns",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &UDPProtocol,
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Namespace: "kube-system",
						Name:      "coredns",
					},
				},
			},
		}...)
	}

	return egressRules
}

// CreateServiceSelectorEntityRule creates an entity rule that matches traffic based on service name and namespace.
func CreateServiceSelectorEntityRule(namespace string, name string) v3.EntityRule {
	return v3.EntityRule{
		Services: &v3.ServiceMatch{
			Namespace: namespace,
			Name:      name,
		},
	}
}

func KubernetesAppSelector(deploymentNames ...string) string {
	expressions := []string{}
	for _, deploymentName := range deploymentNames {
		expressions = append(expressions, fmt.Sprintf("k8s-app == '%s'", deploymentName))
	}
	return strings.Join(expressions, " || ")
}

func Ports(ports ...uint16) []numorstring.Port {
	nsPorts := []numorstring.Port{}
	for _, port := range ports {
		nsPorts = append(nsPorts, numorstring.Port{MinPort: port, MaxPort: port})
	}

	return nsPorts
}

func CalicoSystemDefaultDeny(namespace string) *v3.NetworkPolicy {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      CalicoComponentDefaultDenyPolicyName,
			Namespace: namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     CalicoTierName,
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
		},
	}
}

// Entity rules not belonging to Calico/Tigera components.
var KubeAPIServerEntityRule = v3.EntityRule{
	Services: &v3.ServiceMatch{
		Namespace: "default",
		Name:      "kubernetes",
	},
}

// Konnectivity agents proxy apiserver traffic into the cluster. AKS and GKE label them differently.
var KonnectivityAgentEntityRule = v3.EntityRule{
	NamespaceSelector: "kubernetes.io/metadata.name == 'kube-system'",
	Selector:          "app == 'konnectivity-agent' || k8s-app == 'konnectivity-agent'",
}

// Helper creates a helper for building network policies for multi-tenant capable components.
// It takes two arguments:
// - mt: true if running in multi-tenant mode, false otherwise.
// - ns: The tenant's namespce.
func Helper(mt bool, ns string) *NetworkPolicyHelper {
	return &NetworkPolicyHelper{
		multiTenant: mt,
		ns:          ns,
	}
}

// DefaultHelper returns a NetworkPolicyHelper configured for services that
// only run in single-tenant clusters.
func DefaultHelper() *NetworkPolicyHelper {
	return &NetworkPolicyHelper{
		multiTenant: false,
		ns:          "",
	}
}

type NetworkPolicyHelper struct {
	multiTenant bool
	ns          string
}

func (h *NetworkPolicyHelper) namespace(def string) string {
	if !h.multiTenant {
		return def
	}
	return h.ns
}

// ESGatewayEntityRule returns an entity rule that selects es-gateway pods in the given namespace.
func (h *NetworkPolicyHelper) ESGatewayEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway", 5554)
}

func (h *NetworkPolicyHelper) ESGatewaySourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway")
}

func (h *NetworkPolicyHelper) ESGatewayServiceSelectorEntityRule() v3.EntityRule {
	return CreateServiceSelectorEntityRule(h.namespace("tigera-elasticsearch"), "tigera-secure-es-gateway-http")
}

func (h *NetworkPolicyHelper) LinseedEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed", 8444)
}

func (h *NetworkPolicyHelper) LinseedSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed")
}

func (h *NetworkPolicyHelper) DashboardInstallerEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("tigera-elasticsearch"), "dashboards-installer")
}

func (h *NetworkPolicyHelper) DashboardInstallerSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-elasticsearch"), "dashboards-installer")
}

func (h *NetworkPolicyHelper) LinseedServiceSelectorEntityRule() v3.EntityRule {
	return CreateServiceSelectorEntityRule(h.namespace("tigera-elasticsearch"), "tigera-linseed")
}

func (h *NetworkPolicyHelper) ManagerEntityRule() v3.EntityRule {
	return CreateEntityRule(h.namespace("calico-system"), "calico-manager", 9443)
}

func (h *NetworkPolicyHelper) ManagerSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("calico-system"), "calico-manager")
}

func (h *NetworkPolicyHelper) APIServerSourceEntityRule(v operatorv1.ProductVariant) v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("calico-system"), "calico-apiserver")
}

func (h *NetworkPolicyHelper) PolicyRecommendationSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace(common.CalicoNamespace), "tigera-policy-recommendation")
}

func (h *NetworkPolicyHelper) IntrusionDetectionSourceEntityRule() v3.EntityRule {
	return CreateSourceEntityRule(h.namespace("tigera-intrusion-detection"), "intrusion-detection-controller")
}

// DeprecatedAllowTigeraNetworkPolicyObject returns a CNP object with the
// allow-tigera tier on the name as helper for deprecating this old Tier.
func DeprecatedAllowTigeraNetworkPolicyObject(name, namespace string) client.Object {
	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkPolicy",
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-tigera." + name,
			Namespace: namespace,
		},
	}
}

const PrometheusSelector = "k8s-app == 'tigera-prometheus'"

var PrometheusEntityRule = v3.EntityRule{
	NamespaceSelector: "kubernetes.io/metadata.name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
	Ports:             Ports(9095),
}

var PrometheusSourceEntityRule = v3.EntityRule{
	NamespaceSelector: "name == 'tigera-prometheus'",
	Selector:          PrometheusSelector,
}

// ExternalDestination is a parsed egress target: the host as written plus the
// resolved TCP port.
type ExternalDestination struct {
	Host string
	Port uint16
}

// ParseExternalDestination extracts the host and port from an endpoint, which may
// be a bare "host:port" or a URL. When a URL carries no explicit port the scheme's
// default is used. It reports false when no port can be determined.
func ParseExternalDestination(endpoint string) (ExternalDestination, bool) {
	if host, portStr, err := net.SplitHostPort(endpoint); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			return ExternalDestination{Host: host, Port: uint16(p)}, true
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ExternalDestination{}, false
	}
	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			return ExternalDestination{Host: u.Hostname(), Port: uint16(p)}, true
		}
	}
	switch u.Scheme {
	case "https":
		return ExternalDestination{Host: u.Hostname(), Port: 443}, true
	case "http":
		return ExternalDestination{Host: u.Hostname(), Port: 80}, true
	}
	return ExternalDestination{}, false
}

// clusterService splits an in-cluster Service DNS name --
// <service>.<namespace>.svc[.cluster.local] -- into its namespace and name.
// Each element is checked with the upstream DNS-label validator rather than a
// pattern of our own.
func clusterService(host string) (namespace, name string, ok bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 3 || parts[2] != "svc" {
		return "", "", false
	}
	for _, p := range append([]string{parts[0], parts[1]}, parts[3:]...) {
		if len(validation.IsDNS1123Label(p)) > 0 {
			return "", "", false
		}
	}
	return parts[1], parts[0], true
}

// ExternalDestinationEntityRule builds the tightest destination rule available for
// an external endpoint:
//
//   - a literal IP becomes an exact /32 or /128 net;
//   - a hostname becomes a Domains rule, but only when allowDomains is set —
//     domain-based rules require the egress-access-control license feature;
//   - otherwise the destination is left open and only the port is constrained.
//
// The last case is a deliberate fallback: without the license feature we cannot
// name the host, and dropping the rule entirely would break egress.
func ExternalDestinationEntityRule(dest ExternalDestination, allowDomains bool) v3.EntityRule {
	rule := v3.EntityRule{Ports: Ports(dest.Port)}
	// An in-cluster Service is matched by service, not by domain: Calico resolves
	// Domains rules from observed DNS answers, which does not cover a ClusterIP
	// reached through the cluster domain.
	if ns, name, ok := clusterService(dest.Host); ok {
		// A service match carries the Service's own ports; Calico rejects a rule
		// that sets both ("cannot specify ports with a service selector").
		return CreateServiceSelectorEntityRule(ns, name)
	}
	if ip := net.ParseIP(dest.Host); ip != nil {
		suffix := "/128"
		if ip.To4() != nil {
			suffix = "/32"
		}
		rule.Nets = []string{ip.String() + suffix}
		return rule
	}
	if allowDomains && dest.Host != "" {
		rule.Domains = []string{dest.Host}
	}
	return rule
}
