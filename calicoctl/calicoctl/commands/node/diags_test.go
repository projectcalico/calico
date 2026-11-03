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

package node

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("container runtime detection for node diags", func() {
	DescribeTable("findContainerRuntime",
		func(available []string, want string) {
			lookPath := func(name string) (string, error) {
				for _, a := range available {
					if a == name {
						return "/usr/bin/" + name, nil
					}
				}
				return "", errors.New("not found")
			}
			Expect(findContainerRuntime(lookPath)).To(Equal(want))
		},
		Entry("prefers docker when present", []string{"docker", "nerdctl", "crictl"}, "docker"),
		Entry("uses nerdctl when docker missing", []string{"nerdctl", "crictl"}, "nerdctl"),
		Entry("uses crictl on containerd-only nodes", []string{"crictl"}, "crictl"),
		Entry("empty when nothing available", []string{}, ""),
		Entry("ignores unrelated binaries", []string{"kubectl", "ctr"}, ""),
	)

	DescribeTable("containerIpsetCmdFor",
		func(runtime string, findErr error, wantCmd string, wantErrSubstr string) {
			find := func(name string) (string, error) {
				Expect(name).To(Equal("calico-node"))
				if findErr != nil {
					return "", findErr
				}
				return "abc123def", nil
			}
			cmd, err := containerIpsetCmdFor(runtime, find)
			if wantErrSubstr != "" {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(wantErrSubstr))
				Expect(cmd).To(Equal(""))
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(cmd).To(Equal(wantCmd))
		},
		Entry("docker run", "docker", nil,
			"docker run --rm --privileged --net=host calico/node ipset list", ""),
		Entry("nerdctl run", "nerdctl", nil,
			"nerdctl run --rm --privileged --net=host calico/node ipset list", ""),
		Entry("crictl exec into calico-node", "crictl", nil,
			"crictl exec abc123def ipset list", ""),
		Entry("crictl missing container", "crictl", errors.New("no container matching \"calico-node\" found"),
			"", "crictl"),
		Entry("no runtime", "", nil,
			"", "no supported container runtime"),
	)

	It("containerRuntimes preference order is docker, nerdctl, crictl", func() {
		Expect(containerRuntimes).To(Equal([]string{"docker", "nerdctl", "crictl"}))
	})
})
