// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"fmt"
	"io"
	"os/exec"
)

type CmdIface interface {
	SetStdin(io.Reader)
	SetStdout(io.Writer)
	SetStderr(io.Writer)
	Run() error
	Start() error
	Kill() error
	Wait() error
	Output() ([]byte, error)
	StdoutPipe() (io.ReadCloser, error)
	String() string
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

func (c *cmdAdapter) SetStdout(w io.Writer) {
	c.Stdout = w
}

func (c *cmdAdapter) SetStderr(w io.Writer) {
	c.Stderr = w
}

func (c *cmdAdapter) Run() error {
	return (*exec.Cmd)(c).Run()
}

func (c *cmdAdapter) Start() error {
	return (*exec.Cmd)(c).Start()
}

func (c *cmdAdapter) Kill() error {
	return (*exec.Cmd)(c).Process.Kill()
}

func (c *cmdAdapter) Wait() error {
	return (*exec.Cmd)(c).Wait()
}

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func (c *cmdAdapter) StdoutPipe() (io.ReadCloser, error) {
	return (*exec.Cmd)(c).StdoutPipe()
}

func (c *cmdAdapter) String() string {
	return fmt.Sprintf("%v", (*exec.Cmd)(c))
}
