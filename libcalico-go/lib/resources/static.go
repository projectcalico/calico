// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package resources

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	// DefaultAllowProfileName is the name of a profile provided by Calico that
	// has allow all ingress and egress rules.
	DefaultAllowProfileName = "projectcalico-default-allow"
)

// DefaultAllowProfile returns a single profile kvp with default allow rules.
// This profile can be attached to host endpoints to allow traffic in the
// absence of policy.
func DefaultAllowProfile() *model.KVPair {
	// Create the profile
	profile := v3.NewProfile()
	profile.ObjectMeta = metav1.ObjectMeta{
		Name: DefaultAllowProfileName,
	}
	profile.Spec = v3.ProfileSpec{
		Ingress: []v3.Rule{{Action: v3.Allow}},
		Egress:  []v3.Rule{{Action: v3.Allow}},
	}

	// Embed the profile in a KVPair.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name: DefaultAllowProfileName,
			Kind: v3.KindProfile,
		},
		Value:    profile,
		Revision: "0",
	}
}
