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
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

type CalicoReleaseVersions struct {
	// Dir is the directory to store the pinned version file.
	Dir string

	ProductVersion      string
	ReleaseBranchPrefix string

	OperatorCfg     OperatorConfig
	OperatorVersion string

	versionFilePath string
}

func (p *CalicoReleaseVersions) GenerateFile() (version.Versions, error) {
	ver := version.New(p.ProductVersion)

	tmplData := &calicoTemplateData{
		BaseDomain:     hashreleaseserver.BaseDomain,
		ProductVersion: p.ProductVersion,
		Operator: registry.Component{
			Version:  p.OperatorVersion,
			Image:    p.OperatorCfg.Image,
			Registry: p.OperatorCfg.Registry,
		},
		ReleaseBranch: fmt.Sprintf("%s-%s", p.ReleaseBranchPrefix, ver.Stream()),
	}

	tmpl, err := template.New("versions").Parse(calicoTemplate)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return nil, err
	}
	p.versionFilePath = PinnedVersionFilePath(p.Dir)
	pinnedVersionFile, err := os.Create(p.versionFilePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = pinnedVersionFile.Close() }()
	if err := tmpl.Execute(pinnedVersionFile, tmplData); err != nil {
		return nil, err
	}
	return nil, nil
}

// ImageList return a list of Calico images built by this repo for release validation.
// It excludes flannel and the Tigera operator images as those are validated separately.
func (p *CalicoReleaseVersions) ImageList() ([]string, error) {
	components, err := RetrieveImageComponents(p.Dir)
	if err != nil {
		return nil, err
	}

	// Exclude flannel (not built by Calico) and the Tigera operator.
	componentNames := make([]string, 0, len(components))
	for name, component := range components {
		if strings.HasPrefix(component.Image, p.OperatorCfg.Image) || name == flannelComponentName {
			continue
		}
		componentNames = append(componentNames, component.Image)
	}
	return componentNames, nil
}

func (p *CalicoReleaseVersions) FlannelVersion() (string, error) {
	versions, err := retrievePinnedVersion(p.Dir)
	if err != nil {
		return "", err
	}
	return versions.Components[flannelComponentName].Version, nil
}
