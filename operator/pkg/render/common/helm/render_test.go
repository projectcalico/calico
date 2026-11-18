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

package helm_test

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"

	"github.com/projectcalico/calico/operator/pkg/render/common/helm"
)

const crdYAML = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
`

func testChart() *chart.Chart {
	return &chart.Chart{
		Metadata: &chart.Metadata{APIVersion: chart.APIVersionV2, Name: "demo", Version: "0.1.0"},
		Values:   map[string]any{"replicas": 1},
		Templates: []*chart.File{
			{Name: "templates/deployment.yaml", Data: []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
  namespace: {{ .Release.Namespace }}
spec:
  replicas: {{ .Values.replicas }}
`)},
			{Name: "templates/serviceaccount.yaml", Data: []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Release.Name }}
`)},
			{Name: "templates/job.yaml", Data: []byte(`apiVersion: batch/v1
kind: Job
metadata:
  name: certgen
  annotations:
    "helm.sh/hook": pre-install
`)},
			{Name: "templates/NOTES.txt", Data: []byte(`Installed {{ .Release.Name }}.`)},
		},
		Files: []*chart.File{{Name: "crds/widgets.yaml", Data: []byte(crdYAML)}},
	}
}

var _ = Describe("Render", func() {
	It("renders manifests in install order and splits out hooks and notes", func() {
		out, err := helm.Render(testChart(), map[string]any{"replicas": 3}, "rel", "ns1", false)
		Expect(err).NotTo(HaveOccurred())

		Expect(out.Manifest).To(HavePrefix("---\n# Source: demo/templates/serviceaccount.yaml\n"))
		sa := strings.Index(out.Manifest, "kind: ServiceAccount")
		deploy := strings.Index(out.Manifest, "kind: Deployment")
		Expect(sa).To(BeNumerically("<", deploy), "ServiceAccount must come before Deployment in install order")
		Expect(out.Manifest).To(ContainSubstring("# Source: demo/templates/deployment.yaml\n"))
		Expect(out.Manifest).To(ContainSubstring("  namespace: ns1\nspec:\n  replicas: 3\n"))
		Expect(out.Manifest).NotTo(ContainSubstring("kind: Job"))
		Expect(out.Manifest).NotTo(ContainSubstring("Installed"))

		Expect(out.Hooks).To(HaveLen(1))
		Expect(out.Hooks[0].Name).To(Equal("certgen"))
		Expect(out.Hooks[0].Events).To(ConsistOf(release.HookPreInstall))
	})

	It("includes CRDs first only when asked", func() {
		out, err := helm.Render(testChart(), nil, "rel", "ns1", true)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Manifest).To(HavePrefix("---\n# Source: demo/crds/widgets.yaml\n" + crdYAML))

		out, err = helm.Render(testChart(), nil, "rel", "ns1", false)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Manifest).NotTo(ContainSubstring("CustomResourceDefinition"))
	})

	It("rejects values that fail the chart schema", func() {
		ch := testChart()
		ch.Schema = []byte(`{"type":"object","properties":{"replicas":{"type":"integer"}}}`)
		_, err := helm.Render(ch, map[string]any{"replicas": "three"}, "rel", "ns1", false)
		Expect(err).To(HaveOccurred())
	})

	It("rejects a chart whose kubeVersion excludes the default capabilities", func() {
		ch := testChart()
		ch.Metadata.KubeVersion = ">= 1.99.0"
		_, err := helm.Render(ch, nil, "rel", "ns1", false)
		Expect(err).To(MatchError(ContainSubstring("incompatible with Kubernetes")))
	})

	It("rejects an invalid release name", func() {
		_, err := helm.Render(testChart(), nil, "Not_Valid", "ns1", false)
		Expect(err).To(HaveOccurred())
	})
})
