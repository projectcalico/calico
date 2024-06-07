// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"os"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

type ExtClientOpts struct {
	IPv6Enabled bool
}

func RunExtClient(namePrefix string) *containers.Container {
	return RunExtClientWithOpts(namePrefix, ExtClientOpts{})
}

func RunExtClientWithOpts(namePrefix string, opts ExtClientOpts) *containers.Container {
	wd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred(), "failed to get working directory")
	c := containers.Run(
		namePrefix,
		containers.RunOpts{
			AutoRemove: true,
		},
		"--privileged",                    // So that we can add routes inside the container.
		"-v", wd+"/../bin:/usr/local/bin", // Map in the test-connectivity binary etc.
		utils.Config.BusyboxImage,
		"/bin/sh", "-c", "sleep 1000")

	if opts.IPv6Enabled {
		c.Exec("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0")
		c.Exec("sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0")
		c.Exec("sysctl", "-w", "net.ipv6.conf.lo.disable_ipv6=0")
		c.Exec("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	}

	return c
}
