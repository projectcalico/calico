// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.
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

package conntrack_test

import (
	"errors"
	"io"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/conntrack"
)

var _ = Describe("Conntrack", func() {
	var conntrack *Conntrack
	var cmdRec *cmdRecorder
	BeforeEach(func() {
		cmdRec = &cmdRecorder{}
		conntrack = NewWithCmdShim(cmdRec.newCmd)
	})
	It("IPv4: Should remove all directions", func() {
		conntrack.RemoveConntrackFlows(4, net.ParseIP("10.0.0.1"))
		Expect(cmdRec.cmdArgs).To(Equal([][]string{
			[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
			[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
		}))
	})
	It("IPv6: Should remove all directions", func() {
		conntrack.RemoveConntrackFlows(6, net.ParseIP("fe80::beef"))
		Expect(cmdRec.cmdArgs).To(Equal([][]string{
			[]string{"--family", "ipv6", "--delete", "--orig-src", "fe80::beef"},
			[]string{"--family", "ipv6", "--delete", "--reply-src", "fe80::beef"},
		}))
	})
	It("should panic on unknown IP version", func() {
		Expect(func() { conntrack.RemoveConntrackFlows(9, nil) }).To(Panic())
	})

	Describe("with no flows to delete", func() {
		BeforeEach(func() {
			cmdRec.nextError = errors.New("0 flow entries")
		})

		It("Should remove all directions and not retry", func() {
			conntrack.RemoveConntrackFlows(4, net.ParseIP("10.0.0.1"))
			Expect(cmdRec.cmdArgs).To(Equal([][]string{
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
			}))
		})
	})
	Describe("with a transient error", func() {
		BeforeEach(func() {
			cmdRec.nextError = errors.New("who knows")
		})

		It("Should remove all directions and retry", func() {
			conntrack.RemoveConntrackFlows(4, net.ParseIP("10.0.0.1"))
			Expect(cmdRec.cmdArgs).To(Equal([][]string{
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
			}))
		})
	})
	Describe("with a persistent error", func() {
		BeforeEach(func() {
			cmdRec.persistentError = errors.New("who knows")
		})

		It("Should remove all directions and retry", func() {
			conntrack.RemoveConntrackFlows(4, net.ParseIP("10.0.0.1"))
			Expect(cmdRec.cmdArgs).To(Equal([][]string{
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--orig-src", "10.0.0.1"},

				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
				[]string{"--family", "ipv4", "--delete", "--reply-src", "10.0.0.1"},
			}))
		})
	})
})

type cmdRecorder struct {
	commands        []*mockCmd
	cmdArgs         [][]string
	nextError       error
	persistentError error
}

func (r *cmdRecorder) newCmd(name string, arg ...string) CmdIface {
	Expect(name).To(Equal("conntrack"))
	mc := &mockCmd{}
	if r.nextError != nil {
		mc.err = r.nextError
		r.nextError = nil
	}
	if r.persistentError != nil {
		mc.err = r.persistentError
	}
	r.commands = append(r.commands, mc)
	r.cmdArgs = append(r.cmdArgs, arg)
	return mc
}

type mockCmd struct {
	err    error
	stderr io.Writer
}

func (m *mockCmd) SetStderr(w io.Writer) {
	m.stderr = w
}

func (m *mockCmd) Run() error {
	if m.err != nil {
		_, _ = m.stderr.Write([]byte(m.err.Error()))
	}
	return m.err
}
