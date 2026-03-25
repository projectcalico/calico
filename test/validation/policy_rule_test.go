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
