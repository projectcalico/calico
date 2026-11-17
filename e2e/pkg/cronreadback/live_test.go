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

package cronreadback

import (
	"strings"
	"testing"

	. "github.com/onsi/gomega"
)

// liveFixture is a CronWorkflow shaped as the ArgoCI cron expansion generates
// it, cut down to a few steps:
//   - a matrix step whose entries differ in E2E_TEST_CONFIG, so they share one
//     template and pass the config as a task argument;
//   - a step that only inherits the globalPrologue default;
//   - a step that sets the config in its own env as well as inheriting the default;
//   - a step with no config, whose main script mentions one;
//   - a template and an exit handler that no entrypoint task runs.
const liveFixture = `{
  "apiVersion": "argoproj.io/v1alpha1",
  "kind": "CronWorkflow",
  "metadata": {
    "name": "e2e-bpf-master",
    "annotations": {"argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/master/.argoci/cron/e2e-bpf.yaml"}
  },
  "spec": {
    "schedule": "10 21 * * 4",
    "workflowMetadata": {
      "labels": {"CI_GIT_REF_TYPE": "NIGHTLY", "CI_GIT_REPO_NAME": "calico"},
      "annotations": {
        "workflows.GI_GIT_REPO_NAME": "calico",
        "workflows.GI_GIT_CLONED_BRANCH": "master",
        "workflows.GI_GIT_REF_TYPE": "NIGHTLY",
        "workflows.GI_GIT_PR_NUMBER": "none",
        "argoci-viewer/source-url": "https://github.com/projectcalico/calico/blob/master/.argoci/cron/e2e-bpf.yaml"
      }
    },
    "workflowSpec": {
      "entrypoint": "argoci-condensed-entrypoint",
      "onExit": "argoci-condensed-exit-handler",
      "arguments": {"parameters": [{"name": "CI_GIT_REPO_NAME", "value": "calico"}]},
      "templateDefaults": {"script": {"env": [{"name": "CI_HOME", "value": "/src"}]}},
      "templates": [
        {"name": "argoci-condensed-entrypoint",
         "dag": {"tasks": [
           {"name": "arm64-smoke-tests-aks-arm64-stable-1-azure-", "template": "arm64-smoke-tests-aks-arm64",
            "arguments": {"parameters": [
              {"name": "E2E_TEST_CONFIG", "value": "e2e/config/bpf/aks-bpf-nobgp.yaml"},
              {"name": "AZ_NETWORK_PLUGIN", "value": "azure"}]}},
           {"name": "arm64-smoke-tests-aks-arm64-stable-1-none-", "template": "arm64-smoke-tests-aks-arm64",
            "arguments": {"parameters": [
              {"name": "E2E_TEST_CONFIG", "value": "e2e/config/bpf/aks-bpf-encap.yaml"},
              {"name": "AZ_NETWORK_PLUGIN", "value": "none"}]}},
           {"name": "wireguard", "template": "wireguard"},
           {"name": "eks-eks-w-calico-cni-calico", "template": "eks-eks-w-calico-cni-calico"},
           {"name": "bpf-mini-scale-runs", "template": "bpf-mini-scale-runs"}]}},
        {"name": "arm64-smoke-tests-aks-arm64",
         "metadata": {"labels": {"ci-step": "arm64-smoke-tests-aks-arm64"}},
         "inputs": {"parameters": [{"name": "E2E_TEST_CONFIG"}, {"name": "AZ_NETWORK_PLUGIN"}]},
         "script": {
           "image": "gcr.io/example/ci:latest",
           "command": ["bash", "-e"],
           "env": [
             {"name": "PROVISIONER", "value": "azr-aks"},
             {"name": "E2E_TEST_CONFIG", "value": "{{inputs.parameters.E2E_TEST_CONFIG}}"},
             {"name": "AZ_NETWORK_PLUGIN", "value": "{{inputs.parameters.AZ_NETWORK_PLUGIN}}"}],
           "source": "CI_POD_STOPPED=false\n# BEGIN argoci:prologue\nexport E2E_TEST_CONFIG=\"${E2E_TEST_CONFIG:-e2e/config/bpf/bpf.yaml}\"\n# END argoci:prologue\n(\n# BEGIN argoci:main-script\n.argoci/scripts/body_standard.sh\n# END argoci:main-script\n) &\n"}},
        {"name": "wireguard",
         "script": {
           "image": "gcr.io/example/ci:latest",
           "command": ["bash", "-e"],
           "env": [{"name": "PROVISIONER", "value": "gcp-kubeadm"}],
           "source": "CI_POD_STOPPED=false\n# BEGIN argoci:prologue\ncd \"${CI_HOME}/${CI_GIT_DIR}\"\nexport FUNCTIONAL_AREA=\"${FUNCTIONAL_AREA:-bpf.yml}\"\nexport E2E_TEST_CONFIG=\"${E2E_TEST_CONFIG:-e2e/config/bpf/bpf.yaml}\"\n# END argoci:prologue\n(\n# BEGIN argoci:main-script\n.argoci/scripts/body_standard.sh\n# END argoci:main-script\n) &\n"}},
        {"name": "eks-eks-w-calico-cni-calico",
         "script": {
           "image": "gcr.io/example/ci:latest",
           "command": ["bash", "-e"],
           "env": [
             {"name": "E2E_TEST_CONFIG", "value": "e2e/config/bpf/eks-bpf.yaml"},
             {"name": "PROVISIONER", "value": "aws-eks"}],
           "source": "CI_POD_STOPPED=false\n# BEGIN argoci:prologue\nexport E2E_TEST_CONFIG=\"${E2E_TEST_CONFIG:-e2e/config/bpf/bpf.yaml}\"\n# END argoci:prologue\n(\n# BEGIN argoci:main-script\n.argoci/scripts/body_standard.sh\n# END argoci:main-script\n) &\n"}},
        {"name": "bpf-mini-scale-runs",
         "script": {
           "image": "gcr.io/example/ci:latest",
           "command": ["bash", "-e"],
           "env": [{"name": "PROVISIONER", "value": "gcp-kubeadm"}],
           "source": "CI_POD_STOPPED=false\n# BEGIN argoci:prologue\ncd \"${CI_HOME}/${CI_GIT_DIR}\"\n# END argoci:prologue\n(\n# BEGIN argoci:main-script\nexport E2E_TEST_CONFIG=\"${E2E_TEST_CONFIG:-e2e/config/bpf/decoy.yaml}\"\n# END argoci:main-script\n) &\n"}},
        {"name": "unreferenced",
         "script": {
           "image": "gcr.io/example/ci:latest",
           "command": ["bash", "-e"],
           "env": [{"name": "E2E_TEST_CONFIG", "value": "e2e/config/bpf/orphan.yaml"}],
           "source": "true\n"}},
        {"name": "argoci-condensed-exit-handler",
         "steps": [[{"name": "slack", "template": "unreferenced", "continueOn": {"failed": true}}]]}
      ]
    }
  }
}`

// hoistedFixture is a CronWorkflow whose steps all set the same config, which
// the expansion states once in templateDefaults instead of in each template.
const hoistedFixture = `{
  "metadata": {"name": "e2e-iptables-master"},
  "spec": {"workflowSpec": {
    "entrypoint": "argoci-condensed-entrypoint",
    "templateDefaults": {"script": {"env": [
      {"name": "CI_HOME", "value": "/src"},
      {"name": "E2E_TEST_CONFIG", "value": "e2e/config/iptables/shared.yaml"}]}},
    "templates": [
      {"name": "argoci-condensed-entrypoint",
       "dag": {"tasks": [{"name": "first", "template": "first"}, {"name": "second", "template": "second"}]}},
      {"name": "first", "script": {"env": [{"name": "PROVISIONER", "value": "aws-eks"}], "source": "true\n"}},
      {"name": "second", "script": {"env": [{"name": "PROVISIONER", "value": "azr-aks"}], "source": "true\n"}}
    ]}}
}`

func TestParseLive(t *testing.T) {
	RegisterTestingT(t)

	live, err := parseLive([]byte(liveFixture))
	Expect(err).NotTo(HaveOccurred())
	Expect(live.Name).To(Equal("e2e-bpf-master"))

	// A matrix's entries share a template, so each takes its config from its
	// task's arguments, under the task's name.
	Expect(live.Cells).To(HaveKeyWithValue("arm64-smoke-tests-aks-arm64-stable-1-azure-", "e2e/config/bpf/aks-bpf-nobgp.yaml"))
	Expect(live.Cells).To(HaveKeyWithValue("arm64-smoke-tests-aks-arm64-stable-1-none-", "e2e/config/bpf/aks-bpf-encap.yaml"))

	// With no env of its own, a step runs the globalPrologue default.
	Expect(live.Cells).To(HaveKeyWithValue("wireguard", "e2e/config/bpf/bpf.yaml"))

	// The env wins over the prologue default, as it does in the shell.
	Expect(live.Cells).To(HaveKeyWithValue("eks-eks-w-calico-cni-calico", "e2e/config/bpf/eks-bpf.yaml"))
}

func TestParseLiveSkipsCellsWithoutConfig(t *testing.T) {
	RegisterTestingT(t)

	live, err := parseLive([]byte(liveFixture))
	Expect(err).NotTo(HaveOccurred())

	// A default exported in the main script is not the prologue's.
	Expect(live.Cells).NotTo(HaveKey("bpf-mini-scale-runs"))

	// Only the entrypoint's tasks are cells, not the templates they run or
	// the ones nothing runs.
	Expect(live.Cells).NotTo(HaveKey("unreferenced"))
	Expect(live.Cells).NotTo(HaveKey("argoci-condensed-entrypoint"))
	Expect(live.Cells).NotTo(HaveKey("arm64-smoke-tests-aks-arm64"))
	Expect(live.Cells).To(HaveLen(4))
}

func TestParseLiveTemplateDefaults(t *testing.T) {
	RegisterTestingT(t)

	live, err := parseLive([]byte(hoistedFixture))
	Expect(err).NotTo(HaveOccurred())

	Expect(live.Cells).To(Equal(map[string]string{
		"first":  "e2e/config/iptables/shared.yaml",
		"second": "e2e/config/iptables/shared.yaml",
	}))
}

func TestParseLiveTemplateDefaultsOtherVariable(t *testing.T) {
	RegisterTestingT(t)

	other := strings.Replace(hoistedFixture, `"E2E_TEST_CONFIG"`, `"E2E_TEST_CONFIG_OLD"`, 1)

	live, err := parseLive([]byte(other))
	Expect(err).NotTo(HaveOccurred())

	Expect(live.Cells).To(BeEmpty())
}

func TestParseLiveTaskWithoutTheArgument(t *testing.T) {
	RegisterTestingT(t)

	// The shared template reads its config from an argument this task omits.
	renamed := strings.Replace(liveFixture, `{"name": "E2E_TEST_CONFIG", "value": "e2e/config/bpf/aks-bpf-encap.yaml"}`, `{"name": "OTHER", "value": "x"}`, 1)

	live, err := parseLive([]byte(renamed))
	Expect(err).NotTo(HaveOccurred())

	Expect(live.Cells).NotTo(HaveKey("arm64-smoke-tests-aks-arm64-stable-1-none-"))
	Expect(live.Cells).To(HaveKey("arm64-smoke-tests-aks-arm64-stable-1-azure-"))
}

func TestParseLiveRequiresEntrypointDAG(t *testing.T) {
	RegisterTestingT(t)

	renamed := strings.Replace(liveFixture, `"entrypoint": "argoci-condensed-entrypoint"`, `"entrypoint": "main"`, 1)

	_, err := parseLive([]byte(renamed))

	Expect(err).To(MatchError(ContainSubstring("no entrypoint DAG")))
}

func TestParseLiveRejectsBadJSON(t *testing.T) {
	RegisterTestingT(t)

	_, err := parseLive([]byte("not json"))
	Expect(err).To(HaveOccurred())
}
