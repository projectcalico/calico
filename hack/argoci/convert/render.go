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

package convert

import (
	"fmt"
	"strings"
)

// render serialises the CronWorkflow. It builds the YAML by hand (rather than
// yaml.Marshal) so we get exact control over the test-vars literal block and
// CONVERTER-TODO comments. Output validity is asserted by round-trip
// unmarshalling in the tests.
func render(opts EmitOptions, tasks []taskView) string {
	var b strings.Builder

	fmt.Fprintf(&b, "apiVersion: argoproj.io/v1alpha1\n")
	fmt.Fprintf(&b, "kind: CronWorkflow\n")
	fmt.Fprintf(&b, "metadata:\n")
	fmt.Fprintf(&b, "  name: %s\n", opts.Name)
	fmt.Fprintf(&b, "  namespace: argoci\n")
	fmt.Fprintf(&b, "  labels:\n")
	fmt.Fprintf(&b, "    repo: calico\n")
	fmt.Fprintf(&b, "    branch: %s\n", opts.Branch)
	fmt.Fprintf(&b, "spec:\n")
	fmt.Fprintf(&b, "  schedules:\n")
	fmt.Fprintf(&b, "    - %q\n", opts.Schedule)
	fmt.Fprintf(&b, "  timezone: UTC\n")
	fmt.Fprintf(&b, "  concurrencyPolicy: Forbid\n")
	fmt.Fprintf(&b, "  failedJobsHistoryLimit: 3\n")
	fmt.Fprintf(&b, "  successfulJobsHistoryLimit: 3\n")
	fmt.Fprintf(&b, "  workflowMetadata:\n")
	fmt.Fprintf(&b, "    generateName: %s-\n", opts.Name)
	fmt.Fprintf(&b, "    labels:\n")
	fmt.Fprintf(&b, "      repo: calico\n")
	fmt.Fprintf(&b, "      type: Nightly\n")
	fmt.Fprintf(&b, "      branch: %s\n", opts.Branch)
	fmt.Fprintf(&b, "      dashboard: calico-oss\n")
	fmt.Fprintf(&b, "  workflowSpec:\n")
	fmt.Fprintf(&b, "    entrypoint: pipeline\n")
	fmt.Fprintf(&b, "    onExit: exit-handler\n")
	fmt.Fprintf(&b, "    # RELEASE_STREAM is derived from `branch` by global_prologue.sh; not passed here.\n")
	fmt.Fprintf(&b, "    arguments:\n")
	fmt.Fprintf(&b, "      parameters:\n")
	fmt.Fprintf(&b, "        - name: reponame\n          value: calico\n")
	fmt.Fprintf(&b, "        - name: repoURL\n          value: git@github.com:projectcalico/calico.git\n")
	fmt.Fprintf(&b, "        - name: branch\n          value: %s\n", opts.Branch)
	fmt.Fprintf(&b, "    nodeSelector:\n      role: argoci\n")
	fmt.Fprintf(&b, "    tolerations:\n      - key: argoci\n        operator: Exists\n")
	// The container image, command and envFrom secrets live in the shared
	// e2e-test / e2e-sweep-destroy WorkflowTemplates (templateDefaults does NOT
	// cross templateRef boundaries), so the cron carries none of that — only
	// the workflow-level scheduling above and the DAG below.
	fmt.Fprintf(&b, "    templates:\n")
	fmt.Fprintf(&b, "      - name: pipeline\n")
	fmt.Fprintf(&b, "        dag:\n")
	fmt.Fprintf(&b, "          tasks:\n")
	for _, t := range tasks {
		renderTask(&b, t)
	}
	// The exit-handler and the e2e-test / sweep-destroy templates it and the
	// tasks reference are cluster WorkflowTemplates in .argoci/templates/,
	// resolved via templateRef.
	fmt.Fprintf(&b, "      - name: exit-handler\n")
	fmt.Fprintf(&b, "        steps:\n")
	fmt.Fprintf(&b, "          - - name: sweep-destroy\n")
	fmt.Fprintf(&b, "              continueOn:\n                failed: true\n")
	fmt.Fprintf(&b, "              templateRef:\n                name: e2e-sweep-destroy\n                template: sweep-destroy\n")
	fmt.Fprintf(&b, "    metrics:\n")
	fmt.Fprintf(&b, "      prometheus:\n")
	fmt.Fprintf(&b, "        - name: workflow_details\n")
	fmt.Fprintf(&b, "          help: \"Start time and status of workflow\"\n")
	fmt.Fprintf(&b, "          labels:\n")
	fmt.Fprintf(&b, "            - key: repo\n              value: calico\n")
	fmt.Fprintf(&b, "            - key: type\n              value: cron\n")
	fmt.Fprintf(&b, "            - key: status\n              value: \"{{workflow.status}}\"\n")
	fmt.Fprintf(&b, "          gauge:\n            realtime: false\n            value: \"{{workflow.creationTimestamp.s}}\"\n")

	return b.String()
}

// renderTask writes a single DAG task at 12-space base indentation.
func renderTask(b *strings.Builder, t taskView) {
	for _, r := range t.Todos {
		fmt.Fprintf(b, "            # CONVERTER-TODO: %s\n", r)
	}
	fmt.Fprintf(b, "            - name: %s\n", t.Name)
	if t.Depends != "" {
		fmt.Fprintf(b, "              depends: %q\n", t.Depends)
	}
	fmt.Fprintf(b, "              templateRef:\n")
	fmt.Fprintf(b, "                name: e2e-test\n")
	fmt.Fprintf(b, "                template: e2e-test\n")
	if len(t.Items) > 0 {
		fmt.Fprintf(b, "              withItems:\n")
		for _, item := range t.Items {
			pairs := make([]string, 0, len(item))
			for _, p := range item {
				pairs = append(pairs, fmt.Sprintf("%s: %q", p.K, p.V))
			}
			fmt.Fprintf(b, "                - { %s }\n", strings.Join(pairs, ", "))
		}
	}
	fmt.Fprintf(b, "              arguments:\n")
	fmt.Fprintf(b, "                parameters:\n")
	fmt.Fprintf(b, "                  - name: cpu-requests\n                    value: %q\n", t.CPURequests)
	fmt.Fprintf(b, "                  - name: mem-requests\n                    value: %q\n", t.MemRequests)
	fmt.Fprintf(b, "                  - name: test-vars\n")
	fmt.Fprintf(b, "                    value: |\n")
	for _, line := range t.VarLines {
		// A single env value may itself contain newlines (e.g. an embedded
		// kind config or JSON blob). Indent EVERY physical line, otherwise a
		// continuation at column 0 terminates the YAML literal block.
		for _, phys := range strings.Split(line, "\n") {
			fmt.Fprintf(b, "                      %s\n", phys)
		}
	}
}
