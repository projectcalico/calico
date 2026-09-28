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
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestBGPPeer_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "node and nodeSelector both set is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					Node:         "mynode",
					NodeSelector: "all()",
					PeerIP:       "10.0.0.1",
					ASNumber:     numorstring.ASNumber(64512),
				},
			},
			wantErr: "node and nodeSelector cannot both be set",
		},
		{
			name: "peerIP and peerSelector both set is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:       "10.0.0.1",
					PeerSelector: "all()",
					ASNumber:     numorstring.ASNumber(64512),
				},
			},
			wantErr: "peerIP and peerSelector cannot both be set",
		},
		{
			name: "peerSelector with asNumber is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerSelector: "all()",
					ASNumber:     numorstring.ASNumber(64512),
				},
			},
			wantErr: "asNumber must be empty when peerSelector is set",
		},
		{
			name: "localWorkloadSelector with peerIP is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					LocalWorkloadSelector: "all()",
					PeerIP:                "10.0.0.1",
					ASNumber:              numorstring.ASNumber(64512),
				},
			},
			wantErr: "peerIP must be empty when localWorkloadSelector is set",
		},
		{
			name: "localWorkloadSelector with peerSelector is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					LocalWorkloadSelector: "all()",
					PeerSelector:          "all()",
					ASNumber:              numorstring.ASNumber(64512),
				},
			},
			wantErr: "peerSelector must be empty when localWorkloadSelector is set",
		},
		{
			name: "localWorkloadSelector without asNumber is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					LocalWorkloadSelector: "all()",
				},
			},
			wantErr: "asNumber is required when localWorkloadSelector is set",
		},
		{
			name: "localWorkloadSelector with asNumber is accepted",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					LocalWorkloadSelector: "all()",
					ASNumber:              numorstring.ASNumber(64512),
				},
			},
		},
		{
			name: "reachableBy without peerIP is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerSelector: "all()",
					ReachableBy:  "10.0.0.254",
				},
			},
			wantErr: "reachableBy must be empty when peerIP is empty",
		},
		{
			name: "reachableBy with peerIP is accepted",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:      "10.0.0.1",
					ASNumber:    numorstring.ASNumber(64512),
					ReachableBy: "10.0.0.254",
				},
			},
		},
		{
			name: "keepOriginalNextHop with nextHopMode is rejected",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:              "10.0.0.1",
					ASNumber:            numorstring.ASNumber(64512),
					KeepOriginalNextHop: true,
					NextHopMode:         ptr.To(v3.NextHopMode(v3.NextHopModeSelf)),
				},
			},
			wantErr: "keepOriginalNextHop and nextHopMode cannot both be set",
		},
		{
			name: "keepOriginalNextHop alone is accepted",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:              "10.0.0.1",
					ASNumber:            numorstring.ASNumber(64512),
					KeepOriginalNextHop: true,
				},
			},
		},
		{
			name: "nextHopMode alone is accepted",
			obj: &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:      "10.0.0.1",
					ASNumber:    numorstring.ASNumber(64512),
					NextHopMode: ptr.To(v3.NextHopMode(v3.NextHopModeKeep)),
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

func TestBGPPeer_PeerIPValidation(t *testing.T) {
	const wantErr = "peerIP must be an IP address"

	tests := []struct {
		name    string
		peerIP  string
		wantErr string
	}{
		{name: "IPv4 address", peerIP: "10.0.0.1"},
		{name: "IPv6 address", peerIP: "fd00::1"},
		{name: "IPv4 with port", peerIP: "10.0.0.1:179"},
		{name: "bracketed IPv6 with port", peerIP: "[fd00::1]:179"},
		{name: "not an IP at all", peerIP: "not-an-ip", wantErr: wantErr},
		{name: "out of range IPv4 octets", peerIP: "999.999.999.999", wantErr: wantErr},
		{name: "unbracketed IPv6 that looks like host:port", peerIP: "fd00::1:179"},
		{name: "port zero", peerIP: "10.0.0.1:0", wantErr: wantErr},
		{name: "port above 65535", peerIP: "10.0.0.1:99999", wantErr: wantErr},
		{name: "bracketed IPv6 with port zero", peerIP: "[fd00::1]:0", wantErr: wantErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := &v3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgppeer")},
				Spec: v3.BGPPeerSpec{
					PeerIP:   tt.peerIP,
					ASNumber: numorstring.ASNumber(64512),
				},
			}
			if tt.wantErr != "" {
				expectCreateFails(t, peer, tt.wantErr)
			} else {
				expectCreateSucceeds(t, peer)
			}
		})
	}
}

// TestBGPPeer_ASNumberBounds checks that the 4-byte AS number range applies to
// BGPPeer too, which shares the ASNumber type with BGPConfiguration.
func TestBGPPeer_ASNumberBounds(t *testing.T) {
	newPeer := func(asNumber int64) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "BGPPeer",
				"metadata":   map[string]interface{}{"name": uniqueName("bgppeer")},
				"spec": map[string]interface{}{
					"peerIP":   "10.0.0.1",
					"asNumber": asNumber,
				},
			},
		}
	}

	t.Run("above maximum", func(t *testing.T) {
		expectCreateFails(t, newPeer(4294967296), "asNumber")
	})
	t.Run("4-byte AS number above INT32_MAX", func(t *testing.T) {
		expectCreateSucceeds(t, newPeer(4200000001))
	})
}
