// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"embed"
	"fmt"
	"strings"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// crdFiles contains the v3 CRD YAML definitions.
//
//go:embed config/crd/*.yaml
var crdFiles embed.FS

// AllCRDs loads and returns all embedded v3 CRD definitions.
func AllCRDs() ([]*v1.CustomResourceDefinition, error) {
	var crds []*v1.CustomResourceDefinition
	entries, err := crdFiles.ReadDir("config/crd")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded CRD directory: %w", err)
	}
	for _, d := range entries {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			continue
		}
		rawYAML, err := crdFiles.ReadFile("config/crd/" + d.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded CRD %s: %w", d.Name(), err)
		}
		var crd v1.CustomResourceDefinition
		if err := yaml.Unmarshal(rawYAML, &crd); err != nil {
			return nil, fmt.Errorf("failed to unmarshal CRD %s: %w", d.Name(), err)
		}
		crds = append(crds, &crd)
	}
	return crds, nil
}
