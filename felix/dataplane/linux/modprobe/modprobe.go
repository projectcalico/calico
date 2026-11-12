// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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

package modprobe

import "os/exec"

const (
	cmdModProbe = "modprobe"

	// Kernel module needed for SCTP protocol support on some kernels
	ModuleConntrackSCTP = "nf_conntrack_proto_sctp"

	// Kernel module to enable wireguard encryption.
	ModuleWireguard = "wireguard"

	// Kernel module needed for nftables flowtable offload.
	ModuleFlowTable = "nf_flow_table"
)

type ModProbe struct {
	module string
	newCmd CmdFactory
}

type Cmd interface {
	Output() ([]byte, error)
}

type CmdFactory func(name string, arg ...string) Cmd

func NewRealCmd(name string, arg ...string) Cmd {
	cmd := exec.Command(name, arg...)
	return (*cmdAdapter)(cmd)
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func New(module string, newCmd CmdFactory) ModProbe {
	return ModProbe{module, newCmd}
}

func (m ModProbe) Exec() (string, error) {
	cmd := m.newCmd(cmdModProbe, m.module)
	out, err := cmd.Output()
	return string(out), err
}
