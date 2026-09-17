// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package validation_test

import (
	"context"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRule_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "HTTP match with protocol UDP is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("UDP")),
							HTTP:     &v3.HTTPMatch{Methods: []string{"GET"}},
						},
					},
				},
			},
			wantErr: "rules with HTTP match must have protocol TCP or unset",
		},
		{
			name: "HTTP match with action Deny is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action: v3.Deny,
							HTTP:   &v3.HTTPMatch{Methods: []string{"GET"}},
						},
					},
				},
			},
			wantErr: "HTTP match is only valid on Allow rules",
		},
		{
			name: "destination services with ports is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
							Destination: v3.EntityRule{
								Services: &v3.ServiceMatch{Name: "my-svc", Namespace: "default"},
								Ports:    []numorstring.Port{numorstring.SinglePort(80)},
							},
						},
					},
				},
			},
			wantErr: "ports and notPorts cannot be specified with services",
		},
		{
			name: "HTTP match with TCP and Allow is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
							HTTP:     &v3.HTTPMatch{Methods: []string{"GET"}},
						},
					},
				},
			},
		},
		{
			name: "HTTP match with numeric protocol 6 (TCP) is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromInt(6)),
							HTTP:     &v3.HTTPMatch{Methods: []string{"GET"}},
						},
					},
				},
			},
		},
		{
			name: "HTTP match with numeric protocol 17 (UDP) is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromInt(17)),
							HTTP:     &v3.HTTPMatch{Methods: []string{"GET"}},
						},
					},
				},
			},
			wantErr: "rules with HTTP match must have protocol TCP or unset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestICMPFields_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "ICMP code without type is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("ICMP")),
							ICMP:     &v3.ICMPFields{Code: ptr.To(0)},
						},
					},
				},
			},
			wantErr: "ICMP code specified without an ICMP type",
		},
		{
			name: "ICMP with type and code is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("ICMP")),
							ICMP:     &v3.ICMPFields{Type: ptr.To(8), Code: ptr.To(0)},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestRule_ICMP_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "ICMP fields with non-ICMP protocol is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("TCP")),
							ICMP:     &v3.ICMPFields{Type: ptr.To(8)},
						},
					},
				},
			},
			wantErr: "ICMP fields require protocol to be ICMP or ICMPv6",
		},
		{
			name: "ICMP protocol with ipVersion 6 is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:    v3.Allow,
							Protocol:  ptr.To(numorstring.ProtocolFromString("ICMP")),
							IPVersion: ptr.To(6),
						},
					},
				},
			},
			wantErr: "protocol ICMP requires ipVersion 4",
		},
		{
			name: "ICMPv6 protocol with ipVersion 4 is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:    v3.Allow,
							Protocol:  ptr.To(numorstring.ProtocolFromString("ICMPv6")),
							IPVersion: ptr.To(4),
						},
					},
				},
			},
			wantErr: "protocol ICMPv6 requires ipVersion 6",
		},
		{
			name: "ICMP protocol with ipVersion 4 is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:    v3.Allow,
							Protocol:  ptr.To(numorstring.ProtocolFromString("ICMP")),
							IPVersion: ptr.To(4),
						},
					},
				},
			},
		},
		{
			name: "ICMP fields with ICMP protocol is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: ptr.To(numorstring.ProtocolFromString("ICMP")),
							ICMP:     &v3.ICMPFields{Type: ptr.To(8)},
						},
					},
				},
			},
		},
		{
			name: "notProtocol ICMP with ipVersion 6 is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:      v3.Allow,
							NotProtocol: ptr.To(numorstring.ProtocolFromString("ICMP")),
							IPVersion:   ptr.To(6),
						},
					},
				},
			},
			wantErr: "protocol ICMP requires ipVersion 4",
		},
		{
			name: "notProtocol ICMPv6 with ipVersion 4 is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:      v3.Allow,
							NotProtocol: ptr.To(numorstring.ProtocolFromString("ICMPv6")),
							IPVersion:   ptr.To(4),
						},
					},
				},
			},
			wantErr: "protocol ICMPv6 requires ipVersion 6",
		},
		{
			name: "notProtocol ICMP with ipVersion 4 is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:      v3.Allow,
							NotProtocol: ptr.To(numorstring.ProtocolFromString("ICMP")),
							IPVersion:   ptr.To(4),
						},
					},
				},
			},
		},
		{
			name: "notProtocol ICMPv6 with ipVersion 6 is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action:      v3.Allow,
							NotProtocol: ptr.To(numorstring.ProtocolFromString("ICMPv6")),
							IPVersion:   ptr.To(6),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestEntityRule_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "services with namespaceSelector is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action: v3.Allow,
							Source: v3.EntityRule{
								Services:          &v3.ServiceMatch{Name: "svc1"},
								NamespaceSelector: "all()",
							},
						},
					},
				},
			},
			wantErr: "cannot specify NamespaceSelector and Services on the same rule",
		},
		{
			name: "services with serviceAccounts is rejected",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action: v3.Allow,
							Source: v3.EntityRule{
								Services:        &v3.ServiceMatch{Name: "svc1"},
								ServiceAccounts: &v3.ServiceAccountMatch{Names: []string{"sa1"}},
							},
						},
					},
				},
			},
			wantErr: "cannot specify ServiceAccounts and Services on the same rule",
		},
		{
			name: "services with name alone is accepted",
			obj: &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
				Spec: v3.NetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Action: v3.Allow,
							Source: v3.EntityRule{
								Services: &v3.ServiceMatch{Name: "svc1"},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestNetworkPolicy_Defaults(t *testing.T) {
	np := &v3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np-dflt"), Namespace: "default"},
		Spec: v3.NetworkPolicySpec{
			Ingress: []v3.Rule{
				{Action: v3.Allow},
			},
		},
	}
	mustCreate(t, np)

	got := &v3.NetworkPolicy{}
	if err := testClient.Get(context.Background(), client.ObjectKeyFromObject(np), got); err != nil {
		t.Fatalf("failed to get network policy: %v", err)
	}
	if got.Spec.Tier != "default" {
		t.Fatalf("expected tier to default to %q, got %q", "default", got.Spec.Tier)
	}
}

func TestRule_ProtocolValidation(t *testing.T) {
	const wantErr = "protocol must be a name"

	tests := []struct {
		name     string
		protocol numorstring.Protocol
		wantErr  string
	}{
		{name: "TCP", protocol: numorstring.ProtocolFromString("TCP")},
		{name: "UDPLite", protocol: numorstring.ProtocolFromString("UDPLite")},
		{name: "numeric 6", protocol: numorstring.ProtocolFromInt(6)},
		{name: "numeric 255", protocol: numorstring.ProtocolFromInt(255)},
		{name: "unknown name", protocol: numorstring.ProtocolFromString("NOTAPROTO"), wantErr: wantErr},
		{name: "numeric zero", protocol: numorstring.ProtocolFromInt(0), wantErr: wantErr},
	}

	for _, tt := range tests {
		for field, mkRule := range map[string]func(numorstring.Protocol) v3.Rule{
			"protocol": func(p numorstring.Protocol) v3.Rule {
				return v3.Rule{Action: v3.Allow, Protocol: &p}
			},
			"notProtocol": func(p numorstring.Protocol) v3.Rule {
				return v3.Rule{Action: v3.Allow, NotProtocol: &p}
			},
		} {
			t.Run(field+" "+tt.name, func(t *testing.T) {
				np := &v3.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: uniqueName("np"), Namespace: "default"},
					Spec:       v3.NetworkPolicySpec{Ingress: []v3.Rule{mkRule(tt.protocol)}},
				}
				if tt.wantErr != "" {
					expectCreateFails(t, np, tt.wantErr)
				} else {
					expectCreateSucceeds(t, np)
				}
			})
		}
	}
}

// numorstring canonicalises a protocol name on the way in, so the raw values a
// kubectl apply can carry only reach the API server through an unstructured object.
func TestRule_ProtocolValidationRawValues(t *testing.T) {
	for _, tt := range []struct {
		name     string
		protocol interface{}
		wantErr  string
	}{
		{name: "canonical name", protocol: "TCP"},
		{name: "lowercase name", protocol: "tcp", wantErr: "protocol must be a name"},
		{name: "unknown name", protocol: "NOTAPROTO", wantErr: "protocol must be a name"},
		{name: "number above 255", protocol: int64(256), wantErr: "protocol must be a name"},
		{name: "negative number", protocol: int64(-1), wantErr: "protocol must be a name"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "projectcalico.org/v3",
					"kind":       "NetworkPolicy",
					"metadata": map[string]interface{}{
						"name":      uniqueName("np-proto"),
						"namespace": "default",
					},
					"spec": map[string]interface{}{
						"ingress": []interface{}{
							map[string]interface{}{"action": "Allow", "protocol": tt.protocol},
						},
					},
				},
			}
			if tt.wantErr != "" {
				expectCreateFails(t, obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, obj)
			}
		})
	}
}
