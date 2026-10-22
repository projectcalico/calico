// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package charttest

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
)

func TestImageRepositoriesAreLowercaseAndTagsPreserved(t *testing.T) {
	for _, chart := range []string{"calico", "tigera-operator"} {
		t.Run(chart, func(t *testing.T) {
			dir, err := filepath.Abs("../" + chart)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string]string{"version": "v3.32.0-RC1"}
			if chart == "calico" {
				for _, component := range []string{"calico", "cniPlugins", "node", "kubeControllers", "typha", "webhooks", "flannelMigration"} {
					values[component+".registry"] = "Quay.IO/Team"
					values[component+".image"] = "Mixed/Image"
				}
			} else {
				values["tigeraOperator.registry"] = "Quay.IO/Team"
				values["tigeraOperator.image"] = "Mixed/Operator"
				values["tigeraOperator.version"] = "v1.RC1"
				values["calicoctl.image"] = "Quay.IO/Team/Mixed/CLI"
				values["calicoctl.tag"] = "v3.RC1"
			}
			rendered := helm.RenderTemplateContext(t, t.Context(), &helm.Options{SetValues: values}, dir, "case-test", nil)
			var images int
			for _, line := range strings.Split(rendered, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "image:") && !strings.HasPrefix(line, "- image:") {
					continue
				}
				image := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "- "), "image:")), "\"'")
				colon := strings.LastIndex(image, ":")
				if colon < 0 {
					continue
				}
				if image[:colon] != strings.ToLower(image[:colon]) {
					t.Fatalf("repository is not lowercase: %s", image)
				}
				images++
			}
			if images == 0 {
				t.Fatal("no container images rendered")
			}
			if chart == "tigera-operator" && !strings.Contains(rendered, "quay.io/team/mixed/operator:v1.RC1") {
				t.Fatal("operator tag casing changed")
			}
			if chart == "calico" && !strings.Contains(rendered, "quay.io/team/mixed/image:v3.32.0-RC1") {
				t.Fatal("image tag casing changed")
			}
		})
	}
}
