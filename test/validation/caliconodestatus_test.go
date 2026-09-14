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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCalicoNodeStatus_UpdatePeriodBounds(t *testing.T) {
	newStatus := func(seconds int64) *unstructured.Unstructured {
		return &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "projectcalico.org/v3",
				"kind":       "CalicoNodeStatus",
				"metadata":   map[string]interface{}{"name": uniqueName("nodestatus")},
				"spec": map[string]interface{}{
					"node":                "mynode",
					"classes":             []interface{}{"Agent"},
					"updatePeriodSeconds": seconds,
				},
			},
		}
	}

	t.Run("below minimum", func(t *testing.T) {
		expectCreateFails(t, newStatus(-1), "updatePeriodSeconds")
	})
	t.Run("above maximum", func(t *testing.T) {
		expectCreateFails(t, newStatus(86401), "updatePeriodSeconds")
	})
	t.Run("at the bounds", func(t *testing.T) {
		expectCreateSucceeds(t, newStatus(0))
		expectCreateSucceeds(t, newStatus(86400))
	})
}
