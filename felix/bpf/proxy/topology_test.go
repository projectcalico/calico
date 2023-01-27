// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.
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

package proxy_test

import (
	"testing"

	"github.com/projectcalico/calico/felix/bpf/proxy"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestShouldAppendTopologyAwareEndpoint(t *testing.T) {
	testCases := []struct {
		nodeLabels      map[string]string
		hintsAnnotation string
		zoneHints       sets.String
		expect          bool
		actual          bool
	}{{
		nodeLabels:      nil,
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		nodeLabels:      map[string]string{"kubernetes.io/arch": "amd64"},
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "auto",
		zoneHints:       nil,
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "disabled",
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "auto",
		zoneHints:       sets.NewString("us-west-2a"),
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "auto",
		zoneHints:       sets.NewString("us-west-2b"),
		expect:          false,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "disabled",
		zoneHints:       sets.NewString("us-west-2b"),
		expect:          true,
	}, {
		nodeLabels:      map[string]string{v1.LabelTopologyZone: "us-west-2a"},
		hintsAnnotation: "dummy",
		zoneHints:       sets.NewString("us-west-2b"),
		expect:          true,
	}}

	for _, tc := range testCases {
		t.Run("ShouldAppendTopologyAwareEndpoint", func(t *testing.T) {
			tc.actual = proxy.ShouldAppendTopologyAwareEndpoint(tc.nodeLabels, tc.hintsAnnotation, tc.zoneHints)
			Expect(tc.actual).To(Equal(tc.expect))
		})
	}
}
