// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
