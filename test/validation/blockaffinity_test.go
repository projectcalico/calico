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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IPAM only writes host and virtual affinities, and older affinities leave the
// type unset.
func TestBlockAffinity_Type(t *testing.T) {
	tests := []struct {
		name    string
		affType string
		wantErr string
	}{
		{name: "unset type is accepted"},
		{name: "host type is accepted", affType: "host"},
		{name: "virtual type is accepted", affType: "virtual"},
		{name: "unknown type is rejected", affType: "bogus", wantErr: `Unsupported value: "bogus"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &v3.BlockAffinity{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("affinity")},
				Spec: v3.BlockAffinitySpec{
					State: v3.StateConfirmed,
					Node:  "mynode",
					Type:  tt.affType,
					CIDR:  "10.0.0.0/26",
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
