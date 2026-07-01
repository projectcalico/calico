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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// emittedCron is the subset of the generated CronWorkflow the tests inspect.
type emittedCron struct {
	Kind string `yaml:"kind"`
	Spec struct {
		WorkflowSpec struct {
			Templates []struct {
				Name string `yaml:"name"`
				DAG  struct {
					Tasks []emittedTask `yaml:"tasks"`
				} `yaml:"dag"`
			} `yaml:"templates"`
		} `yaml:"workflowSpec"`
	} `yaml:"spec"`
}

type emittedTask struct {
	Name        string                          `yaml:"name"`
	Depends     string                          `yaml:"depends"`
	TemplateRef struct{ Name, Template string } `yaml:"templateRef"`
	WithItems   []map[string]string             `yaml:"withItems"`
	Arguments   struct {
		Parameters []struct {
			Name  string `yaml:"name"`
			Value string `yaml:"value"`
		} `yaml:"parameters"`
	} `yaml:"arguments"`
}

func (t emittedTask) param(name string) string {
	for _, p := range t.Arguments.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func pipelineTasks(t *testing.T, c emittedCron) []emittedTask {
	t.Helper()
	for _, tmpl := range c.Spec.WorkflowSpec.Templates {
		if tmpl.Name == "pipeline" {
			return tmpl.DAG.Tasks
		}
	}
	t.Fatal("no 'pipeline' template in emitted cron")
	return nil
}

func emitNftables(t *testing.T) (string, emittedCron, []string) {
	t.Helper()
	p, err := LoadPipeline("testdata/nftables.yml")
	if err != nil {
		t.Fatalf("LoadPipeline: %v", err)
	}
	out, todos := Emit(p, EmitOptions{Name: "e2e-nftables-master", Branch: "master", Schedule: "0 3 * * 2"})
	var c emittedCron
	if err := yaml.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("emitted YAML does not parse: %v\n---\n%s", err, out)
	}
	return out, c, todos
}

func TestEmitValidAndComplete(t *testing.T) {
	_, c, todos := emitNftables(t)

	if c.Kind != "CronWorkflow" {
		t.Errorf("kind = %q, want CronWorkflow", c.Kind)
	}
	if len(todos) != 0 {
		t.Errorf("unexpected CONVERTER-TODOs: %v", todos)
	}

	tasks := pipelineTasks(t, c)
	// One DAG task per Semaphore JOB (matrix stays a single task w/ withItems):
	// arm64(1) + Talos block(3) + EKS(2) + KinD(2) + KubeVirt(1) = 9.
	if got, want := len(tasks), 9; got != want {
		names := make([]string, len(tasks))
		for i, tk := range tasks {
			names[i] = tk.Name
		}
		t.Errorf("task count = %d, want %d: %v", got, want, names)
	}

	for _, tk := range tasks {
		if tk.TemplateRef.Name != "e2e-test" {
			t.Errorf("task %q templateRef.name = %q, want e2e-test", tk.Name, tk.TemplateRef.Name)
		}
		if tk.param("test-vars") == "" {
			t.Errorf("task %q has empty test-vars", tk.Name)
		}
	}
}

func byTestVarsContains(tasks []emittedTask, needle string) *emittedTask {
	for i := range tasks {
		if strings.Contains(tasks[i].param("test-vars"), needle) {
			return &tasks[i]
		}
	}
	return nil
}

func TestEmitMatrixAndEscaping(t *testing.T) {
	_, c, _ := emitNftables(t)
	tasks := pipelineTasks(t, c)

	arm := byTestVarsContains(tasks, "export ENABLE_WIREGUARD='true'")
	if arm == nil {
		t.Fatal("no arm64/WG task found")
	}
	// Matrix job → single task with a 2-entry withItems (the two CLUSTER_IMAGEs).
	if len(arm.WithItems) != 2 {
		t.Errorf("arm64 withItems = %d, want 2", len(arm.WithItems))
	}
	vars := arm.param("test-vars")
	// Matrix axis is emitted as an {{item.X}} reference, not a static value.
	if !strings.Contains(vars, "export CLUSTER_IMAGE='{{item.CLUSTER_IMAGE}}'") {
		t.Errorf("arm64 test-vars missing matrix CLUSTER_IMAGE line:\n%s", vars)
	}
	if strings.Contains(vars, "export CLUSTER_IMAGE='ubuntu") {
		t.Errorf("arm64 test-vars should not carry a static CLUSTER_IMAGE value:\n%s", vars)
	}
	// Regex-heavy K8S_E2E_FLAGS must survive single-quoted with backslashes intact.
	if !strings.Contains(vars, `export K8S_E2E_FLAGS='--ginkgo.focus=(\[sig-calico\]|\[Conformance\])`) {
		t.Errorf("arm64 test-vars K8S_E2E_FLAGS not escaped as expected:\n%s", vars)
	}
}

func TestEmitResourceProfile(t *testing.T) {
	_, c, _ := emitNftables(t)
	tasks := pipelineTasks(t, c)

	kind := byTestVarsContains(tasks, "export PROVISIONER='local-kind'")
	if kind == nil {
		t.Fatal("no local-kind task found")
	}
	if kind.param("cpu-requests") != "3500m" {
		t.Errorf("local-kind cpu-requests = %q, want 3500m", kind.param("cpu-requests"))
	}

	remote := byTestVarsContains(tasks, "export PROVISIONER='gcp-kubeadm'")
	if remote == nil {
		t.Fatal("no gcp-kubeadm task found")
	}
	if remote.param("cpu-requests") != "1000m" {
		t.Errorf("gcp-kubeadm cpu-requests = %q, want 1000m", remote.param("cpu-requests"))
	}
}

func TestEmitKubeVirtDualSelection(t *testing.T) {
	_, c, _ := emitNftables(t)
	tasks := pipelineTasks(t, c)

	kv := byTestVarsContains(tasks, "export E2E_TEST_CONFIG='e2e/config/gcp-kubevirt.yaml'")
	if kv == nil {
		t.Fatal("no KubeVirt task with E2E_TEST_CONFIG found")
	}
	// KubeVirt legitimately carries BOTH the global K8S_E2E_FLAGS and a
	// block-level E2E_TEST_CONFIG; both pass through (runtime precedence picks
	// E2E_TEST_CONFIG). This must not be flagged as a TODO.
	if !strings.Contains(kv.param("test-vars"), "export K8S_E2E_FLAGS=") {
		t.Error("KubeVirt task should still carry the inherited global K8S_E2E_FLAGS")
	}
}
