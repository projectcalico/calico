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

package testconfig

import (
	"strings"
	"testing"
)

const (
	kindSuiteYAML = `
kind: suite
include:
  - sig-calico && Covers:NetworkPolicy
`

	kindCNIYAML = `
kind: cluster
needs:
  - cni/calico.yaml
provides:
  - BGP
`

	kindUpstreamYAML = `
kind: cluster
provides:
  - AWS
upstream:
  - group: "EKS control plane cannot reach the pod network"
    patterns:
      - 'DNS.for.services'
`

	kindQuarantineYAML = `
kind: quarantine
exclude:
  namePatterns:
    - group: "Pods never reach Running on the host-endpoint lane"
      ticket: https://tigera.atlassian.net/browse/CORE-13670
      quarantined: 2026-09-18
      patterns:
        - 'should.allow.traffic.to.a.host.endpoint'
`

	kindPolicyYAML = `
kind: policy
exclude:
  labels:
    - label: Slow
      reason: "too slow for CI"
`

	oldShapeYAML = `
extends: parent.yaml
exclude:
  labels:
    - label: Disruptive
      reason: "breaks cluster state"
`

	oldShapeParentYAML = `
include:
  - sig-calico
`
)

// kindCase is a config file at a path under the config root, and the error
// loading it must cause, or "" when it must load.
type kindCase struct {
	path    string
	content string
	wantErr string
}

func TestKindAcceptsEachShapeInItsDirectory(t *testing.T) {
	checkKindCases(t, []kindCase{
		{path: "suite/policy.yaml", content: kindSuiteYAML},
		{path: "cluster/routing/bgp.yaml", content: kindCNIYAML},
		{path: "cluster/platform/eks.yaml", content: kindUpstreamYAML},
		{path: "quarantine/core-13670.yaml", content: kindQuarantineYAML},
		{path: "ci-base.yaml", content: kindPolicyYAML},
	})
}

// Every key is allowed in a file without a kind, wherever it sits, so the
// validation lands before any config moves to the new shape.
func TestNoKindLoadsAsOldShape(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "suite/parent.yaml", oldShapeParentYAML)
	path := writeFile(t, dir, "suite/lane.yaml", oldShapeYAML)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Include.Labels) != 1 || len(cfg.Exclude.Labels) != 1 {
		t.Errorf("include %v exclude %v, want one of each from the extends chain", cfg.Include.Labels, cfg.Exclude.Labels)
	}
}

func TestKindRejectsForbiddenKeys(t *testing.T) {
	checkKindCases(t, []kindCase{
		{
			path:    "suite/policy.yaml",
			content: "kind: suite\ninclude: [sig-calico]\nexclude:\n  labels:\n    - {label: Slow, reason: slow}\n",
			wantErr: "exclude (line 3) is not allowed in a suite file, which carries only kind, include",
		},
		{
			path:    "cluster/cni/calico.yaml",
			content: "kind: cluster\nextends: base.yaml\nprovides: [CalicoCNI]\n",
			wantErr: "extends (line 2) is not allowed in a cluster file",
		},
		{
			path:    "cluster/cni/calico.yaml",
			content: "kind: cluster\nprovide: [CalicoCNI]\n",
			wantErr: "provide (line 2) is not allowed",
		},
		{
			path:    "cluster/routing/bgp.yaml",
			content: kindUpstreamYAML,
			wantErr: "upstream (line 5) is allowed only in a cluster/platform/ file",
		},
		{
			path:    "quarantine/slow.yaml",
			content: strings.Replace(kindPolicyYAML, "kind: policy", "kind: quarantine", 1),
			wantErr: "a quarantine file excludes by name only",
		},
		{
			path:    "ci-base.yaml",
			content: strings.Replace(kindQuarantineYAML, "kind: quarantine", "kind: policy", 1),
			wantErr: "the policy file excludes by label only",
		},
		{
			path:    "suite/policy.yaml",
			content: strings.Replace(kindSuiteYAML, "kind: suite", "kind: lane", 1),
			wantErr: `kind "lane" is not one of`,
		},
	})
}

func TestKindRejectsWrongDirectory(t *testing.T) {
	checkKindCases(t, []kindCase{
		{path: "suite/bgp.yaml", content: kindCNIYAML, wantErr: "a cluster file belongs in cluster/<dimension>/"},
		{path: "cluster/bgp.yaml", content: kindCNIYAML, wantErr: "a cluster file belongs in cluster/<dimension>/"},
		{path: "policy.yaml", content: kindSuiteYAML, wantErr: "a suite file belongs in suite/"},
		{path: "suite/core-13670.yaml", content: kindQuarantineYAML, wantErr: "a quarantine file belongs in quarantine/"},
		{path: "quarantine/ci-base.yaml", content: kindPolicyYAML, wantErr: "a policy file belongs outside suite/, cluster/ and quarantine/"},
	})
}

// checkKindCases writes each case under its own config root and loads it.
func checkKindCases(t *testing.T, cases []kindCase) {
	t.Helper()
	for _, c := range cases {
		_, err := Load(writeFile(t, t.TempDir(), c.path, c.content))
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("Load(%s) = %v, want it to load", c.path, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("Load(%s) err = %v, want one containing %q", c.path, err, c.wantErr)
		}
	}
}
