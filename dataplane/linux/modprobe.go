// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package intdataplane

import "os/exec"

const (
	// Modprobe binary on the system
	cmdModProbe = "modprobe"

	// Kernel module needed for SCTP protocol support on some kernels
	moduleConntrackSCTP = "nf_conntrack_proto_sctp"

	// Kernel module to enable wireguard encryption.
	moduleWireguard = "wireguard"
)

type modProbe struct {
	module string
	newCmd cmdFactory
}

type cmdIface interface {
	Output() ([]byte, error)
}

type cmdFactory func(name string, arg ...string) cmdIface

func newRealCmd(name string, arg ...string) cmdIface {
	cmd := exec.Command(name, arg...)
	return (*cmdAdapter)(cmd)
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func newModProbe(module string, newCmd cmdFactory) modProbe {
	return modProbe{module, newCmd}
}

func (m modProbe) Exec() (string, error) {
	cmd := m.newCmd(cmdModProbe, m.module)
	out, err := cmd.Output()
	return string(out), err
}
