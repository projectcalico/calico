// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package helm

import (
	"bytes"
	"fmt"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/releaseutil"
)

type Rendered struct {
	Manifest string
	Hooks    []*release.Hook
}

// Render gives the same output as a client-only, dry-run helm install.
// It avoids helm's action package, whose cluster client must implement every
// client-go typed interface and so breaks on each new Kubernetes minor.
func Render(ch *chart.Chart, vals map[string]any, releaseName, namespace string, includeCRDs bool) (*Rendered, error) {
	if err := chartutil.ValidateReleaseName(releaseName); err != nil {
		return nil, fmt.Errorf("release name %q: %w", releaseName, err)
	}
	if err := chartutil.ProcessDependenciesWithMerge(ch, vals); err != nil {
		return nil, err
	}

	caps := chartutil.DefaultCapabilities.Copy()
	opts := chartutil.ReleaseOptions{
		Name:      releaseName,
		Namespace: namespace,
		Revision:  1,
		IsInstall: true,
	}
	values, err := chartutil.ToRenderValuesWithSchemaValidation(ch, vals, opts, caps, false)
	if err != nil {
		return nil, err
	}

	if ch.Metadata.KubeVersion != "" && !chartutil.IsCompatibleRange(ch.Metadata.KubeVersion, caps.KubeVersion.String()) {
		return nil, fmt.Errorf("chart requires kubeVersion: %s which is incompatible with Kubernetes %s", ch.Metadata.KubeVersion, caps.KubeVersion.String())
	}

	var e engine.Engine
	files, err := e.Render(ch, values)
	if err != nil {
		return nil, err
	}
	for name := range files {
		if strings.HasSuffix(name, "NOTES.txt") {
			delete(files, name)
		}
	}

	hooks, manifests, err := releaseutil.SortManifests(files, nil, releaseutil.InstallOrder)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if includeCRDs {
		for _, crd := range ch.CRDObjects() {
			fmt.Fprintf(&b, "---\n# Source: %s\n%s\n", crd.Filename, string(crd.File.Data))
		}
	}
	for _, m := range manifests {
		fmt.Fprintf(&b, "---\n# Source: %s\n%s\n", m.Name, m.Content)
	}
	return &Rendered{Manifest: b.String(), Hooks: hooks}, nil
}
