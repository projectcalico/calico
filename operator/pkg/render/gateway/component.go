// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package gateway

import (
	"fmt"

	envoyapi "github.com/envoyproxy/gateway/api/v1alpha1"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gapi "sigs.k8s.io/gateway-api/apis/v1"
	gapiv1b1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/common"
	rmeta "github.com/projectcalico/calico/operator/pkg/render/common/meta"
	"github.com/projectcalico/calico/operator/pkg/render/common/networkpolicy"
	rgatewayapi "github.com/projectcalico/calico/operator/pkg/render/gatewayapi"
	"github.com/projectcalico/calico/operator/pkg/tls/certificatemanagement"
)

const (
	EnvoyGatewayGroup = "gateway.envoyproxy.io"
	BackendKind       = "Backend"

	// GatewayLabel marks operator-managed UI Gateways; the value is the
	// component's resource prefix. Cleanup lists Gateways by this label to
	// find namespaces holding leftover gateway resources.
	GatewayLabel = "operator.tigera.io/gateway"

	// GatewayNamespaceLabel marks a namespace the operator created for a
	// gateway. It is component-agnostic: teardown deletes the namespace only
	// once no labeled Gateway from any component remains, so components that
	// share a namespace never delete it out from under each other.
	GatewayNamespaceLabel = "operator.tigera.io/gateway-namespace"
)

// Configuration holds everything the shared gateway component needs to render
// Gateway API resources for a UI component (Manager or Whisker).
type Configuration struct {
	Hostname         string
	GatewayNamespace string
	GatewayClassName string

	BackendServiceName           string
	BackendPort                  int32
	BackendNamespace             string
	BackendCABundleConfigMapName string

	TLSKeyPair certificatemanagement.KeyPairInterface

	// ResourcePrefix names all generated resources, e.g. "calico-manager" produces
	// "calico-manager-gateway", "calico-manager-route", etc.
	ResourcePrefix string

	// RouteRequestTimeout, when set, becomes the HTTPRoute rule's request
	// timeout; nil keeps the Envoy Gateway default.
	RouteRequestTimeout *string

	// ExtraProxyObjects are variant-specific objects rendered beside the
	// proxy, only when the Gateway shares the backend namespace — elsewhere
	// the GatewayAPI controller provisions per-namespace resources itself.
	ExtraProxyObjects []client.Object

	OpenShift bool
}

// Component renders Gateway API resources for CIG access to a UI component.
func Component(cfg *Configuration) *gatewayComponent {
	return &gatewayComponent{cfg: cfg}
}

type gatewayComponent struct {
	cfg *Configuration
}

func (c *gatewayComponent) ResolveImages(_ *operatorv1.ImageSet) error {
	return nil
}

func (c *gatewayComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *gatewayComponent) Ready() bool {
	return true
}

func (c *gatewayComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	var objs []client.Object

	// Both grants come first because they carry the write permissions the
	// resources below need.
	gwRole, gwBinding := c.gatewayAccess()
	bkRole, bkBinding := c.backendAccess()
	objs = append(objs, gwRole, gwBinding, bkRole, bkBinding)

	// Render the Gateway before the other gateway resources. It carries the
	// cleanup label, so even if a later resource fails to render, cleanup can
	// still discover the gateway resources.
	objs = append(objs, c.gateway())

	if c.cfg.GatewayNamespace != c.cfg.BackendNamespace {
		// Allow the HTTPRoute to reference the backend across namespaces.
		objs = append(objs, c.referenceGrant())
	}

	// The TLS secret is rendered after the Gateway. In a custom gateway
	// namespace the operator gains secret access through the RoleBinding the
	// GatewayAPI controller creates once it sees the Gateway there, so the
	// secret create fails on the first reconcile and succeeds on the retry.
	objs = append(objs,
		c.backend(),
		c.httpRoute(),
		c.tlsSecret(),
	)

	var toDelete []client.Object
	if c.cfg.GatewayNamespace == c.cfg.BackendNamespace {
		// calico-system has an operator-managed default-deny on both variants,
		// and the GatewayAPI controller skips it (lifecycle guard), so the
		// proxy NetworkPolicy is rendered here. In a custom namespace no
		// NetworkPolicy is rendered — the same treatment user-brought Gateways
		// get.
		objs = append(objs, c.proxyNetworkPolicy())
		objs = append(objs, c.cfg.ExtraProxyObjects...)

		// The gateway now shares the backend namespace, so the cross-namespace
		// ReferenceGrant is no longer needed. Delete it here, where the render
		// holds the backend-namespace grant.
		toDelete = append(toDelete, c.referenceGrant())
	}

	return objs, toDelete
}

const (
	gatewayAccessSuffix = "-ingressgateway-access"
	backendAccessSuffix = "-ingressgateway-backend-access"
)

// GatewayName returns the Gateway object's name for a resource prefix, so callers
// that reference the Gateway by name stay in sync with the render.
func GatewayName(prefix string) string { return prefix + "-gateway" }

// RouteName is the HTTPRoute object name for a component's resource prefix.
func RouteName(prefix string) string { return prefix + "-route" }

// gatewayAccess grants the operator the write permissions needed in the gateway namespace; the
// cluster-wide ClusterRole keeps the reads.
func (c *gatewayComponent) gatewayAccess() (*rbacv1.Role, *rbacv1.RoleBinding) {
	return c.access(c.cfg.ResourcePrefix+gatewayAccessSuffix, c.cfg.GatewayNamespace, []rbacv1.PolicyRule{
		{
			APIGroups: []string{gapi.GroupName},
			Resources: []string{"gateways", "httproutes"},
			Verbs:     []string{"create", "update", "delete"},
		},
	})
}

// backendAccess grants the writes needed where the backing Service lives.
func (c *gatewayComponent) backendAccess() (*rbacv1.Role, *rbacv1.RoleBinding) {
	return c.access(c.cfg.ResourcePrefix+backendAccessSuffix, c.cfg.BackendNamespace, []rbacv1.PolicyRule{
		{
			APIGroups: []string{gapi.GroupName},
			Resources: []string{"referencegrants"},
			Verbs:     []string{"create", "update", "delete"},
		},
		{
			APIGroups: []string{EnvoyGatewayGroup},
			Resources: []string{"backends"},
			Verbs:     []string{"create", "update", "delete"},
		},
	})
}

// access builds a Role with rules and a RoleBinding tying it to the operator's
// own ServiceAccount, the identity that renders the gateway resources.
func (c *gatewayComponent) access(name, namespace string, rules []rbacv1.PolicyRule) (*rbacv1.Role, *rbacv1.RoleBinding) {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{GatewayLabel: c.cfg.ResourcePrefix},
		},
		Rules: rules,
	}, &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{GatewayLabel: c.cfg.ResourcePrefix},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      common.OperatorServiceAccount(),
				Namespace: common.OperatorNamespace(),
			},
		},
	}
}

func (c *gatewayComponent) tlsSecret() *corev1.Secret {
	s := c.cfg.TLSKeyPair.Secret(c.cfg.GatewayNamespace)
	s.Type = corev1.SecretTypeTLS
	return s
}

func (c *gatewayComponent) gateway() *gapi.Gateway {
	listenerName := gapi.SectionName(c.cfg.ResourcePrefix + "-https")
	hostname := gapi.Hostname(c.cfg.Hostname)
	tlsSecretName := c.cfg.TLSKeyPair.GetName()

	return &gapi.Gateway{
		TypeMeta: metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      GatewayName(c.cfg.ResourcePrefix),
			Namespace: c.cfg.GatewayNamespace,
			Labels: map[string]string{
				GatewayLabel: c.cfg.ResourcePrefix,
			},
		},
		Spec: gapi.GatewaySpec{
			GatewayClassName: gapi.ObjectName(c.cfg.GatewayClassName),
			Listeners: []gapi.Listener{
				{
					Name:     listenerName,
					Protocol: gapi.HTTPSProtocolType,
					Port:     gapi.PortNumber(443),
					Hostname: &hostname,
					TLS: &gapi.ListenerTLSConfig{
						Mode: ptr.To(gapi.TLSModeTerminate),
						CertificateRefs: []gapi.SecretObjectReference{
							{
								Name: gapi.ObjectName(tlsSecretName),
							},
						},
					},
					AllowedRoutes: &gapi.AllowedRoutes{
						Namespaces: &gapi.RouteNamespaces{
							From: ptr.To(gapi.NamespacesFromSame),
						},
					},
				},
			},
		},
	}
}

func (c *gatewayComponent) httpRoute() *gapi.HTTPRoute {
	gatewayName := gapi.ObjectName(GatewayName(c.cfg.ResourcePrefix))
	sectionName := gapi.SectionName(c.cfg.ResourcePrefix + "-https")
	backendName := gapi.ObjectName(c.cfg.ResourcePrefix + "-backend")
	backendNS := gapi.Namespace(c.cfg.BackendNamespace)
	group := gapi.Group(EnvoyGatewayGroup)

	var timeouts *gapi.HTTPRouteTimeouts
	if c.cfg.RouteRequestTimeout != nil {
		timeouts = &gapi.HTTPRouteTimeouts{Request: ptr.To(gapi.Duration(*c.cfg.RouteRequestTimeout))}
	}

	return &gapi.HTTPRoute{
		TypeMeta: metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RouteName(c.cfg.ResourcePrefix),
			Namespace: c.cfg.GatewayNamespace,
		},
		Spec: gapi.HTTPRouteSpec{
			CommonRouteSpec: gapi.CommonRouteSpec{
				ParentRefs: []gapi.ParentReference{
					{
						Name:        gatewayName,
						SectionName: &sectionName,
					},
				},
			},
			Rules: []gapi.HTTPRouteRule{
				{
					Timeouts: timeouts,
					BackendRefs: []gapi.HTTPBackendRef{
						{
							BackendRef: gapi.BackendRef{
								BackendObjectReference: gapi.BackendObjectReference{
									Group:     &group,
									Kind:      ptr.To(gapi.Kind(BackendKind)),
									Name:      backendName,
									Namespace: &backendNS,
								},
							},
						},
					},
				},
			},
		},
	}
}

func (c *gatewayComponent) backend() *envoyapi.Backend {
	svcFQDN := c.cfg.BackendServiceName + "." + c.cfg.BackendNamespace + ".svc"
	sni := gapi.PreciseHostname(svcFQDN)

	return &envoyapi.Backend{
		TypeMeta: metav1.TypeMeta{Kind: BackendKind, APIVersion: "gateway.envoyproxy.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-backend",
			Namespace: c.cfg.BackendNamespace,
		},
		Spec: envoyapi.BackendSpec{
			Endpoints: []envoyapi.BackendEndpoint{
				{
					FQDN: &envoyapi.FQDNEndpoint{
						Hostname: svcFQDN,
						Port:     c.cfg.BackendPort,
					},
				},
			},
			TLS: &envoyapi.BackendTLSSettings{
				CACertificateRefs: []gapi.LocalObjectReference{
					{
						Group: "",
						Kind:  "ConfigMap",
						Name:  gapi.ObjectName(c.cfg.BackendCABundleConfigMapName),
					},
				},
				SNI: &sni,
			},
		},
	}
}

// ReferenceGrant is written as v1beta1, the only version served by every
// Gateway API bundle we may find pre-installed (OpenShift 4.19 ships v1.2.1,
// and CRDManagementPreferExisting leaves it alone). v1beta1 is still the
// storage version as of Gateway API v1.6.
func (c *gatewayComponent) referenceGrant() *gapiv1b1.ReferenceGrant {
	backendName := gapi.ObjectName(c.cfg.ResourcePrefix + "-backend")

	return &gapiv1b1.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{Kind: "ReferenceGrant", APIVersion: "gateway.networking.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.cfg.ResourcePrefix + "-allow-gateway",
			Namespace: c.cfg.BackendNamespace,
		},
		Spec: gapiv1b1.ReferenceGrantSpec{
			From: []gapiv1b1.ReferenceGrantFrom{
				{
					Group:     gapi.GroupName,
					Kind:      "HTTPRoute",
					Namespace: gapi.Namespace(c.cfg.GatewayNamespace),
				},
			},
			To: []gapiv1b1.ReferenceGrantTo{
				{
					Group: gapi.Group(EnvoyGatewayGroup),
					Kind:  BackendKind,
					Name:  &backendName,
				},
			},
		},
	}
}

// proxyNetworkPolicy creates a Calico NetworkPolicy that allows the Envoy
// proxy pod to function in calico-system (which has a default deny).
func (c *gatewayComponent) proxyNetworkPolicy() *v3.NetworkPolicy {
	gatewayName := GatewayName(c.cfg.ResourcePrefix)
	policyName := networkpolicy.CalicoComponentPolicyPrefix + gatewayName + "-proxy"

	egressRules := networkpolicy.AppendDNSEgressRules(nil, c.cfg.OpenShift)
	egressRules = append(egressRules,
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(
				// The Envoy Gateway controller (the proxy's xDS source) always
				// runs in calico-system, not in this component's backend
				// namespace, which differs for multi-tenant Manager.
				rgatewayapi.DeploymentNamespace, rgatewayapi.GatewayControllerLabel,
				18000, 18001,
			),
		},
		v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: networkpolicy.CreateEntityRule(
				c.cfg.BackendNamespace, c.cfg.BackendServiceName,
				uint16(c.cfg.BackendPort),
			),
		},
	)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: c.cfg.GatewayNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.CalicoTierName,
			Selector: fmt.Sprintf("gateway.envoyproxy.io/owning-gateway-name == '%s'", gatewayName),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"0.0.0.0/0"}},
					Destination: v3.EntityRule{
						// Envoy Gateway remaps privileged ports by adding 10000,
						// so listener port 443 becomes container port 10443.
						Ports: networkpolicy.Ports(10443),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Source:   v3.EntityRule{Nets: []string{"::/0"}},
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(10443),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// DeletionConfiguration is the minimal config needed to identify gateway
// resources for cleanup. No TLS keypair, hostname, or class is required.
type DeletionConfiguration struct {
	ResourcePrefix   string
	StaleNamespace   string
	BackendNamespace string
	TLSSecretName    string
	// ExtraProxyObjects mirrors Configuration.ExtraProxyObjects for cleanup;
	// deleted only when the stale namespace is the backend namespace.
	ExtraProxyObjects []client.Object

	// DeleteNamespace deletes the stale namespace; set it only for a namespace the operator created.
	DeleteNamespace bool

	// TargetNamespace is the namespace to which the Gateway has moved.
	TargetNamespace string
}

// DeletionComponent returns a render.Component whose Objects() puts every
// gateway-managed resource into objsToDelete. The objects carry only TypeMeta
// and ObjectMeta — enough for the component handler to issue Delete calls.
func DeletionComponent(cfg *DeletionConfiguration) *gatewayDeletionComponent {
	return &gatewayDeletionComponent{cfg: cfg}
}

type gatewayDeletionComponent struct {
	cfg *DeletionConfiguration
}

func (c *gatewayDeletionComponent) ResolveImages(_ *operatorv1.ImageSet) error { return nil }
func (c *gatewayDeletionComponent) SupportedOSType() rmeta.OSType              { return rmeta.OSTypeLinux }
func (c *gatewayDeletionComponent) Ready() bool                                { return true }

func (c *gatewayDeletionComponent) Objects() (objsToCreate, objsToDelete []client.Object) {
	staleNS := c.cfg.StaleNamespace
	bkNS := c.cfg.BackendNamespace
	prefix := c.cfg.ResourcePrefix

	objs := []client.Object{
		&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: c.cfg.TLSSecretName, Namespace: staleNS},
		},
		&gapi.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: RouteName(prefix), Namespace: staleNS},
		},
	}

	// The Backend and ReferenceGrant live in the backend namespace, so only the
	// backend namespace's own teardown pass deletes them. A pass for any other
	// namespace has no write access there. On a move into the backend namespace
	// the ReferenceGrant is deleted by the live render instead, which holds the
	// backend grant.
	if staleNS == bkNS && c.cfg.TargetNamespace == "" {
		objs = append(objs,
			&envoyapi.Backend{
				TypeMeta:   metav1.TypeMeta{Kind: BackendKind, APIVersion: "gateway.envoyproxy.io/v1alpha1"},
				ObjectMeta: metav1.ObjectMeta{Name: prefix + "-backend", Namespace: bkNS},
			},
			&gapiv1b1.ReferenceGrant{
				TypeMeta:   metav1.TypeMeta{Kind: "ReferenceGrant", APIVersion: "gateway.networking.k8s.io/v1beta1"},
				ObjectMeta: metav1.ObjectMeta{Name: prefix + "-allow-gateway", Namespace: bkNS},
			},
		)
	}

	if staleNS == bkNS {
		objs = append(objs,
			&v3.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      networkpolicy.CalicoComponentPolicyPrefix + prefix + "-gateway-proxy",
					Namespace: staleNS,
				},
			},
		)
		objs = append(objs, c.cfg.ExtraProxyObjects...)
	}

	// The Gateway goes after the resources found through it, mirroring the render.
	// If an earlier delete fails, it stays and the next reconcile still finds the
	// leftovers by its label.
	objs = append(objs, &gapi.Gateway{
		TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: GatewayName(prefix), Namespace: staleNS},
	})

	// The grants go after the resources they permit deleting. The backend grant
	// is dropped only by the backend namespace's own component.
	objs = append(objs, c.roleBinding(staleNS, gatewayAccessSuffix), c.role(staleNS, gatewayAccessSuffix))
	if staleNS == bkNS && c.cfg.TargetNamespace == "" {
		objs = append(objs, c.roleBinding(bkNS, backendAccessSuffix), c.role(bkNS, backendAccessSuffix))
	}

	// The namespace goes last. Deleting it removes everything inside.
	if c.cfg.DeleteNamespace {
		objs = append(objs, &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: staleNS},
		})
	}

	return nil, objs
}

func (c *gatewayDeletionComponent) role(namespace, suffix string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.cfg.ResourcePrefix + suffix, Namespace: namespace},
	}
}

func (c *gatewayDeletionComponent) roleBinding(namespace, suffix string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.cfg.ResourcePrefix + suffix, Namespace: namespace},
	}
}
