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
	"bufio"
	"io"
	"os/exec"
)

type WriteFlusher interface {
	io.Writer
	Flush() error
}

type WriteCloserFlusher interface {
	io.WriteCloser
	Flush() error
}

type CmdIface interface {
	StdinPipe() (WriteCloserFlusher, error)
	StdoutPipe() (io.ReadCloser, error)

	SetStdin(io.Reader)
	SetStdout(io.Writer)
	SetStderr(io.Writer)

	Start() error
	Wait() error
	Output() ([]byte, error)
	CombinedOutput() ([]byte, error)
}

type cmdFactory func(name string, arg ...string) CmdIface

func newRealCmd(name string, arg ...string) CmdIface {
	cmd := exec.Command(name, arg...)
	return (*cmdAdapter)(cmd)
}

type cmdAdapter exec.Cmd

func (c *cmdAdapter) StdinPipe() (WriteCloserFlusher, error) {
	pipe, err := (*exec.Cmd)(c).StdinPipe()
	if err != nil {
		return nil, err
	}
	buf := bufio.NewWriter(pipe)
	return &BufferedCloser{
		BufWriter: buf,
		Closer:    pipe,
	}, nil
}

type BufferedCloser struct {
	BufWriter WriteFlusher
	Closer    io.Closer
}

func (b *BufferedCloser) Write(p []byte) (n int, err error) {
	return b.BufWriter.Write(p)
}

func (b *BufferedCloser) Flush() error {
	return b.BufWriter.Flush()
}

func (b *BufferedCloser) Close() error {
	return b.Closer.Close()
}

func (c *cmdAdapter) StdoutPipe() (io.ReadCloser, error) {
	return (*exec.Cmd)(c).StdoutPipe()
}

func (c *cmdAdapter) SetStdin(r io.Reader) {
	c.Stdin = r
}

func (c *cmdAdapter) SetStdout(r io.Writer) {
	c.Stdout = r
}

func (c *cmdAdapter) SetStderr(r io.Writer) {
	c.Stderr = r
}

func (c *cmdAdapter) Start() error {
	return (*exec.Cmd)(c).Start()
}

func (c *cmdAdapter) Wait() error {
	return (*exec.Cmd)(c).Wait()
}

func (c *cmdAdapter) Output() ([]byte, error) {
	return (*exec.Cmd)(c).Output()
}

func (c *cmdAdapter) CombinedOutput() ([]byte, error) {
	return (*exec.Cmd)(c).CombinedOutput()
}
