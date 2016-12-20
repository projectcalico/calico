// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package ipsets_test

import (
	"bytes"
	"errors"
	"fmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/set"
	"io"
	"os/exec"
)

// This file contains shared test infrastructure for testing the ipsets package.

func newMockDataplane() *mockDataplane {
	return &mockDataplane{
		IPSetMembers: make(map[string]set.Set),
	}
}

type mockDataplane struct {
	IPSetMembers map[string]set.Set
	Cmds         []CmdIface
}

func (d *mockDataplane) newCmd(name string, arg ...string) CmdIface {
	if name != "ipset" {
		Fail("Unknown command: " + name)
	}

	var cmd CmdIface

	switch arg[0] {
	case "restore":
	case "destroy":
		Expect(len(arg)).To(Equal(2))
		name := arg[1]
		cmd = &destroyCmd{
			Dataplane: d,
			SetName:   name,
		}
	case "list":
		Expect(len(arg)).To(Equal(2))
		Expect(arg[1]).To(Equal("-n")) // Only current use is to list names.
		cmd = &listNamesCmd{
			Dataplane: d,
		}

	default:
		Fail(fmt.Sprintf("Unexpected command %v", arg))
	}

	d.Cmds = append(d.Cmds, cmd)

	return cmd
}

type destroyCmd struct {
	Dataplane *mockDataplane
	SetName   string
}

func (d *destroyCmd) SetStdin(_ io.Reader) {
	Fail("destroyCommand expects no input")
}

func (d *destroyCmd) Output() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (d *destroyCmd) CombinedOutput() ([]byte, error) {
	if _, ok := d.Dataplane.IPSetMembers[d.SetName]; ok {
		// IP set exists.
		return []byte(""), nil // No output on success
	} else {
		// IP set missing.
		return []byte("ipset v6.29: The set with the given name does not exist"),
			&exec.ExitError{} // No need to fill, error not parsed by caller.
	}
}

type listNamesCmd struct {
	Dataplane *mockDataplane
	SetName   string
}

func (d *listNamesCmd) SetStdin(_ io.Reader) {
	Fail("listNamesCmd expects no input")
}

func (d *listNamesCmd) Output() ([]byte, error) {
	var buf bytes.Buffer
	for name := range d.Dataplane.IPSetMembers {
		buf.WriteString(name + "\n")
	}
	return buf.Bytes(), nil
}

func (d *listNamesCmd) CombinedOutput() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}
