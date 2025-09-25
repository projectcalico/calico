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

package operator

import "testing"

func TestImageParts(t *testing.T) {
	for _, tc := range []struct {
		image        string
		expImagePath string
		expImageName string
		shouldErr    bool
	}{
		{
			image:        "tigera/operator",
			expImagePath: "tigera",
			expImageName: "operator",
		},
		{
			image:     "tigera/extra/operator",
			shouldErr: true,
		},
		{
			image:     "operator",
			shouldErr: true,
		},
	} {
		t.Run(tc.image, func(t *testing.T) {
			m := &OperatorManager{
				image: tc.image,
			}
			imagePath, imageName, err := m.imageParts()
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if imagePath != tc.expImagePath {
				t.Errorf("expected image path %s but got %s", tc.expImagePath, imagePath)
			}
			if imageName != tc.expImageName {
				t.Errorf("expected image name %s but got %s", tc.expImageName, imageName)
			}
		})
	}
}

func TestProductRegistryParts(t *testing.T) {
	for _, tc := range []struct {
		registry     string
		expRegistry  string
		expNamespace string
		shouldErr    bool
	}{
		{
			registry:     "my-registry/my-namespace",
			expRegistry:  "my-registry",
			expNamespace: "my-namespace",
		},
		{
			registry:  "my-registry",
			shouldErr: true,
		},
		{
			registry:     "my-registry/extra/my-namespace",
			expRegistry:  "my-registry/extra",
			expNamespace: "my-namespace",
		},
		{
			registry:     "my-registry/extra/more/my-namespace",
			expRegistry:  "my-registry/extra/more",
			expNamespace: "my-namespace",
		},
	} {
		t.Run(tc.registry, func(t *testing.T) {
			m := &OperatorManager{
				productRegistry: tc.registry,
			}
			registry, namespace, err := m.productRegistryParts()
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if registry != tc.expRegistry {
				t.Errorf("expected registry %s but got %s", tc.expRegistry, registry)
			}
			if namespace != tc.expNamespace {
				t.Errorf("expected namespace %s but got %s", tc.expNamespace, namespace)
			}
		})
	}
}
