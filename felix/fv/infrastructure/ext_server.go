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
	"fmt"
	"os"
	"strings"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
)

type ExternalServer struct {
	*containers.Container
	hostIfName string
	workloadIP string
	ports      string
}

func (e *ExternalServer) ToMatcher(explicitPort ...uint16) *connectivity.Matcher {
	var port string
	if len(explicitPort) == 1 {
		port = fmt.Sprintf("%d", explicitPort[0])
	} else if !strings.Contains(e.ports, ",") {
		port = e.ports
	} else {
		panic("Explicit port needed for workload with multiple ports")
	}
	return &connectivity.Matcher{
		IP:         e.workloadIP,
		Port:       port,
		TargetName: fmt.Sprintf("%s on port %s", e.Name, port),
		Protocol:   "tcp",
	}
}

func (e *ExternalServer) SetupRoute() {
	_, err := e.Container.ExecCombinedOutput(
		"sysctl", "-w",
		fmt.Sprintf("net.ipv4.conf.%v.proxy_arp=1", e.hostIfName),
	)
	Expect(err).NotTo(HaveOccurred(), "Failed to enable proxy ARP on host veth.")
	_, err = e.Container.ExecCombinedOutput(
		"ip", "r", "add", e.workloadIP+"/32", "dev", e.hostIfName,
	)
	Expect(err).NotTo(HaveOccurred(), "Failed to add route from host to container NS.")
}

func RunExtServer(name, profile, ip, port, proto string) *ExternalServer {
	wd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred(), "failed to get working directory")

	var protoArg string
	if proto != "" {
		protoArg = "--protocol=" + proto
	}

	interfaceName := conversion.NewConverter().VethNameForWorkload(profile, name)
	c := containers.Run(
		name,
		containers.RunOpts{
			AutoRemove: true,
		},
		"--privileged",                    // So that we can add routes inside the container.
		"-v", wd+"/../bin:/usr/local/bin", // Map in the test-connectivity binary etc.
		utils.Config.FelixImage,
		"/bin/bash", "-c",
		fmt.Sprintf("echo $$ > /tmp/%v; exec test-workload %v '%v' '%v' '%v'",
			name,
			protoArg,
			interfaceName,
			ip,
			port),
	)

	return &ExternalServer{
		Container:  c,
		hostIfName: interfaceName,
		workloadIP: ip,
		ports:      port,
	}
}
