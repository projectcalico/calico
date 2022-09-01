// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package fv_test

import (
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/calicoctl/tests/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	log.AddHook(logutils.ContextHook{})
	log.SetFormatter(&logutils.Formatter{})
}

func TestMultiCluster(t *testing.T) {
	RegisterTestingT(t)

	unpatchEnv, err := PatchEnv("KUBECONFIG", strings.Join([]string{
		"/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/kubectl-config.yaml",
		"/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/kubectl-config-second.yaml",
	}, ":"))
	Expect(err).NotTo(HaveOccurred())
	defer unpatchEnv()

	// Set Calico version in ClusterInformation for both contexts
	out, err := SetCalicoVersion(true, "--context", "main")
	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("Calico version set to"))

	out, err = SetCalicoVersion(true, "--context", "second")
	Expect(err).ToNot(HaveOccurred())
	Expect(out).To(ContainSubstring("Calico version set to"))

	// This check will Fail, kubectl-config.yaml file that we are using for this only contains "main" context.
	out, err = CalicoctlMayFail(true, "--allow-version-mismatch", "get", "node", "--context", "fake")
	Expect(err).To(HaveOccurred())
	Expect(out).To(ContainSubstring("Failed"))

	// This check should Pass
	out = Calicoctl(true, "get", "node", "--context", "main")
	Expect(out).To(ContainSubstring("node4"))

	out = Calicoctl(true, "get", "node", "--context", "second")
	Expect(out).To(ContainSubstring("node8"))

	// This check should Pass proving --context works regardless of its position
	out = Calicoctl(true, "--context", "main", "get", "node")
	Expect(out).To(ContainSubstring("node4"))

	out = Calicoctl(true, "create", "-f", "/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/v3/bgppeer-global.yaml", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	out = Calicoctl(true, "patch", "bgppeer", "globalpeer.name5", "-p", "{\"spec\":{\"asNumber\": \"63445\"}}", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	out = Calicoctl(true, "apply", "-f", "/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/v3/bgppeer-global.yaml", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	out = Calicoctl(true, "replace", "-f", "/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/v3/bgppeer-global.yaml", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	out = Calicoctl(true, "label", "nodes", "node4", "cluster=backend", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	out = Calicoctl(true, "label", "nodes", "node4", "cluster", "--remove", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

	// Calico spesific commands only support context at the beginning.
	out = Calicoctl(true, "--context", "main", "ipam", "show")
	Expect(out).To(ContainSubstring("CIDR"))

	out = Calicoctl(true, "delete", "-f", "/go/src/github.com/projectcalico/calico/calicoctl/test-data/multi-context/v3/bgppeer-global.yaml", "--context", "main")
	Expect(out).To(ContainSubstring("Successfully"))

}
