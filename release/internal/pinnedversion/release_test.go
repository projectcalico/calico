// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package pinnedversion

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestImageList(t *testing.T) {
	v := &CalicoReleaseVersions{
		Dir:                 t.TempDir(),
		ProductVersion:      "v3.33.3",
		ReleaseBranchPrefix: "release",
		OperatorCfg: OperatorConfig{
			Image:    "tigera/operator",
			Registry: "quay.io",
		},
		OperatorVersion: "vA.B.C",
	}

	_, err := v.GenerateFile()
	if err != nil {
		t.Fatalf("Failed to generate file: %v", err)
	}

	p, err := v.ImageList()
	if err != nil {
		t.Fatalf("Failed to get image list: %v", err)
	}
	expected := []string{
		"typha",
		"ctl",
		"node",
		"cni",
		"apiserver",
		"kube-controllers",
		"goldmane",
		"dikastes",
		"envoy-gateway",
		"envoy-proxy",
		"envoy-ratelimit",
		"pod2daemon-flexvol",
		"key-cert-provisioner",
		"csi",
		"node-driver-registrar",
		"cni-windows",
		"node-windows",
		"guardian",
		"whisker",
		"whisker-backend",
	}
	if diff := cmp.Diff(expected, p, cmpopts.SortSlices(func(a, b string) bool {
		return a < b
	})); diff != "" {
		t.Errorf("Image list mismatch (-want +got):\n%s", diff)
	}
}
