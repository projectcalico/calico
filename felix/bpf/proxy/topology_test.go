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

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/projectcalico/calico/felix/bpf/proxy"
)

func TestShouldAppendTopologyAwareEndpoint(t *testing.T) {
	testCases := []struct {
		description     string
		nodeZone        string
		hintsAnnotation string
		//nolint:staticcheck // Ignore SA1019 deprecated until kubernetes/pkg/proxy/types.go fixes sets.String
		zoneHints sets.Set[string]
		expect    bool
		actual    bool
	}{{
		description:     "node zone empty, hints annotation empty, zone hints empty, expect should append topology aware endpoint true",
		nodeZone:        "",
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation empty, zone hints empty, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "",
		zoneHints:       nil,
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation auto, zone hints empty, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "auto",
		zoneHints:       nil,
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation disabled, zone hints empty, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "disabled",
		zoneHints:       nil,
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation auto, zone hints us-west-2a, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "auto",
		zoneHints:       sets.New[string]("us-west-2a"),
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation auto, zone hints us-west-2b, expect should append topology aware endpoint false",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "auto",
		zoneHints:       sets.New[string]("us-west-2b"),
		expect:          false,
	}, {
		description:     "node zone us-west-2a, hints annotation disabled, zone hints us-west-2b, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "disabled",
		zoneHints:       sets.New[string]("us-west-2b"),
		expect:          true,
	}, {
		description:     "node zone us-west-2a, hints annotation dummy, zone hints us-west-2b, expect should append topology aware endpoint true",
		nodeZone:        "us-west-2a",
		hintsAnnotation: "dummy",
		zoneHints:       sets.New[string]("us-west-2b"),
		expect:          true,
	}}

	for _, tc := range testCases {
		t.Run("ShouldAppendTopologyAwareEndpoint", func(t *testing.T) {
			tc.actual = proxy.ShouldAppendTopologyAwareEndpoint(tc.nodeZone, tc.hintsAnnotation, tc.zoneHints)
			Expect(tc.actual).To(Equal(tc.expect))
		})
	}
}
