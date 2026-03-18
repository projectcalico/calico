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

package migration

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// v1 UIDs used across test data and assertions.
var (
	v1TierDefaultUID  = types.UID("v1-uid-tier-default")
	v1TierSecurityUID = types.UID("v1-uid-tier-security")
	v1GNPDenyAllUID   = types.UID("v1-uid-gnp-deny-all")
)

// v1InternalAnnotations simulates the internal metadata annotation that the
// v1 backend stamps on resources. The migration conversion path should strip it.
var v1InternalAnnotations = map[string]string{
	"projectcalico.org/metadata": `{"uid":"ignored","creationTimestamp":"2024-01-01T00:00:00Z"}`,
}

// mainlineV1Resources returns the v1 backend data for the mainline lifecycle
// test: two tiers and a default-tier GNP with an OwnerRef pointing at the
// default tier.
func mainlineV1Resources() map[string][]*model.KVPair {
	return map[string][]*model.KVPair{
		apiv3.KindTier: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
				Value: &apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "default",
						UID:         v1TierDefaultUID,
						Annotations: v1InternalAnnotations,
					},
					Spec: apiv3.TierSpec{Order: ptr.To(float64(100))},
				},
			},
			{
				Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "security"},
				Value: &apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "security",
						UID:         v1TierSecurityUID,
						Annotations: v1InternalAnnotations,
					},
					Spec: apiv3.TierSpec{Order: ptr.To(float64(200))},
				},
			},
		},
		apiv3.KindGlobalNetworkPolicy: {
			{
				Key: model.ResourceKey{Kind: apiv3.KindGlobalNetworkPolicy, Name: "default.deny-all"},
				Value: &apiv3.GlobalNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "default.deny-all",
						UID:         v1GNPDenyAllUID,
						Annotations: v1InternalAnnotations,
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "projectcalico.org/v3",
								Kind:       "Tier",
								Name:       "default",
								UID:        v1TierDefaultUID,
							},
						},
					},
					Spec: apiv3.GlobalNetworkPolicySpec{
						Tier:     "default",
						Selector: "all()",
						Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
					},
				},
			},
		},
		apiv3.KindClusterInformation: {},
	}
}

// mainlineV1ClusterInfo returns a v1 ClusterInformation KVPair with
// DatastoreReady=true, as it would appear before migration begins.
func mainlineV1ClusterInfo() *model.KVPair {
	return &model.KVPair{
		Key: model.ResourceKey{Kind: apiv3.KindClusterInformation, Name: "default"},
		Value: &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: apiv3.ClusterInformationSpec{
				ClusterGUID:    "test-guid-12345",
				ClusterType:    "k8s,bgp",
				CalicoVersion:  "v3.30.0",
				DatastoreReady: ptr.To(true),
			},
		},
	}
}
