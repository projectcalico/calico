// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"embed"
	"fmt"
	"strings"

	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// CRDFiles is a filesystem that contains the CRD YAML definitions.
//
// CRDs are stored in the FS under the crd/ directory.  For example,
// the CRD for the FelixConfiguration resource is stored in the file
// crd/crd.projectcalico.org_felixconfigurations.yaml.
//
//go:embed crd/*.yaml
var CRDFiles embed.FS

func LoadCRD(group, name string) (*v1.CustomResourceDefinition, error) {
	rawYAML, err := CRDFiles.ReadFile("crd/" + group + "_" + name + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load CRD YAML from embedded FS: %w", err)
	}
	var crd v1.CustomResourceDefinition
	err = yaml.Unmarshal(rawYAML, &crd)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CRD YAML: %w", err)
	}
	return &crd, nil
}

func AllCRDs() ([]*v1.CustomResourceDefinition, error) {
	var crds []*v1.CustomResourceDefinition
	entries, err := CRDFiles.ReadDir("crd")
	if err != nil {
		return nil, fmt.Errorf("failed to read CRD directory: %w", err)
	}
	for _, d := range entries {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			continue
		}
		rawYAML, err := CRDFiles.ReadFile("crd/" + d.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to load CRD YAML from embedded FS: %w", err)
		}
		var crd v1.CustomResourceDefinition
		err = yaml.Unmarshal(rawYAML, &crd)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal CRD YAML: %w", err)
		}
		crds = append(crds, &crd)
	}
	return crds, nil
}
