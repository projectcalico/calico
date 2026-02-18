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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestFelixConfiguration_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "routeTableRange and routeTableRanges both set is rejected",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRange:  &v3.RouteTableRange{Min: 1, Max: 250},
					RouteTableRanges: &v3.RouteTableRanges{{Min: 1, Max: 250}},
				},
			},
			wantErr: "routeTableRange and routeTableRanges cannot both be set",
		},
		{
			name: "routeTableRange alone is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRange: &v3.RouteTableRange{Min: 1, Max: 250},
				},
			},
		},
		{
			name: "routeTableRanges alone is accepted",
			obj: &v3.FelixConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("felixconfig")},
				Spec: v3.FelixConfigurationSpec{
					RouteTableRanges: &v3.RouteTableRanges{{Min: 1, Max: 250}},
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
