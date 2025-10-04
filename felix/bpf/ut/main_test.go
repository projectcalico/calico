// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2020  All rights reserved.

package ut_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestMain(m *testing.M) {
	initMapsOnce()
	cleanUpMaps()
	cmd := exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable IPv6 forwarding: %v\n", err)
		os.Exit(1)
	}
	cmd = startBPFLogging()
	rc := m.Run()
	cleanUpMaps()
	stopBPFLogging(cmd)
	os.Exit(rc)
}
