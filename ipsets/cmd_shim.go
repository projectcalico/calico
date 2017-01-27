// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package ipsets

import (
	"io"
	"os/exec"
)

type CmdIface interface {
	SetStdin(io.Reader)
	Output() ([]byte, error)
	CombinedOutput() ([]byte, error)
}

type cmdFactory func(name string, arg ...string) CmdIface

func newRealCmd(name string, arg ...string) CmdIface {
	cmd := exec.Command(name, arg...)
	return (*cmdAdapter)(cmd)
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) SetStdin(r io.Reader) {
	c.Stdin = r
}

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func (c *cmdAdapter) CombinedOutput() ([]byte, error) {
	return (*exec.Cmd)(c).CombinedOutput()
}
