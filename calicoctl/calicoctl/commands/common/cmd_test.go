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

package common

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestCmdResolved(t *testing.T) {
	RegisterTestingT(t)

	// CmdStr path: whitespace-split as before.
	args, display := Cmd{CmdStr: "kubectl get pods -o yaml"}.resolved()
	Expect(args).To(Equal([]string{"kubectl", "get", "pods", "-o", "yaml"}))
	Expect(display).To(Equal("kubectl get pods -o yaml"))

	// CmdArgs path: argv used verbatim so args with embedded whitespace
	// (e.g. a kubectl label selector) survive intact.
	cmd := Cmd{CmdArgs: []string{
		"kubectl", "get", "all", "-n", "kube-system",
		"-l", "k8s-app in (calico-node,kube-proxy)",
		"-o", "yaml",
	}}
	args, display = cmd.resolved()
	Expect(args).To(Equal(cmd.CmdArgs))
	Expect(args[6]).To(Equal("k8s-app in (calico-node,kube-proxy)"))
	Expect(display).To(ContainSubstring("k8s-app in (calico-node,kube-proxy)"))
}
