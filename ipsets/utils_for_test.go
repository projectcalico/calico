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

package ipsets_test

import (
	"bytes"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/set"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// This file contains shared test infrastructure for testing the ipsets package.

var (
	transientFailure = errors.New("Simulated transient failure")
	permanentFailure = errors.New("Simulated permanent failure")
)

func newMockDataplane() *mockDataplane {
	return &mockDataplane{
		IPSetMembers:  make(map[string]set.Set),
		IPSetMetadata: make(map[string]setMetadata),
	}
}

type mockDataplane struct {
	IPSetMembers    map[string]set.Set
	IPSetMetadata   map[string]setMetadata
	Cmds            []CmdIface
	FailNextRestore bool
	FailAllRestores bool
	FailNextDestroy bool

	// Record when various (expected) error cases are hit.
	TriedToDeleteNonExistent bool
	TriedToAddExistent       bool
}

func (d *mockDataplane) ExpectMembers(expected map[string][]string) {
	// Input has a slice for each set, convert to a set for comparison.
	membersToCompare := map[string]set.Set{}
	for name, members := range expected {
		memberSet := set.New()
		for _, member := range members {
			memberSet.Add(member)
		}
		membersToCompare[name] = memberSet
	}
	Expect(d.IPSetMembers).To(Equal(membersToCompare))
}

func (d *mockDataplane) newCmd(name string, arg ...string) CmdIface {
	if name != "ipset" {
		Fail("Unknown command: " + name)
	}

	var cmd CmdIface

	switch arg[0] {
	case "restore":
		Expect(len(arg)).To(Equal(1))
		cmd = &restoreCmd{
			Dataplane: d,
		}
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

type restoreCmd struct {
	Dataplane *mockDataplane
	SetName   string
	Stdin     io.Reader
}

func (d *restoreCmd) SetStdin(r io.Reader) {
	d.Stdin = r
}

func (d *restoreCmd) Output() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (d *restoreCmd) CombinedOutput() ([]byte, error) {
	// Get the input.
	var buf bytes.Buffer
	_, err := buf.ReadFrom(d.Stdin)
	Expect(err).NotTo(HaveOccurred())
	input := buf.String()

	if d.Dataplane.FailNextRestore {
		d.Dataplane.FailNextRestore = false
		return nil, transientFailure
	}
	if d.Dataplane.FailAllRestores {
		return nil, permanentFailure
	}

	// Process it line by line.
	lines := strings.Split(input, "\n")
	commitSeen := false
	for i, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, " ")
		subCmd := parts[0]
		log.WithFields(log.Fields{
			"lineNum": i + 1,
			"line":    line,
			"subCmd":  subCmd,
		}).Info("Mock dataplane, analysing ipset restore line")
		if subCmd != "COMMIT" {
			Expect(commitSeen).To(BeFalse())
		}
		switch subCmd {
		case "create":
			Expect(len(parts)).To(Equal(7))

			name := parts[1]
			Expect(len(name)).To(BeNumerically("<=", MaxIPSetNameLength))
			Expect(name).To(HavePrefix("cali"))

			ipSetType := IPSetType(parts[2])
			Expect(ipSetType.IsValid()).To(BeTrue())

			Expect(parts[3]).To(Equal("family"))
			ipFamily := IPFamily(parts[4])
			Expect(ipFamily.IsValid()).To(BeTrue())

			Expect(parts[5]).To(Equal("maxelem"))
			maxElem, err := strconv.Atoi(parts[6])
			Expect(err).NotTo(HaveOccurred())

			setMetadata := setMetadata{
				Name:    name,
				Family:  ipFamily,
				MaxSize: maxElem,
				Type:    ipSetType,
			}
			log.WithField("setMetadata", setMetadata).Info("Set created")

			if _, ok := d.Dataplane.IPSetMembers[name]; ok {
				return []byte("set exists"), &exec.ExitError{}
			}

			d.Dataplane.IPSetMembers[name] = set.New()
			d.Dataplane.IPSetMetadata[name] = setMetadata
		case "destroy":
			Expect(len(parts)).To(Equal(2))
			name := parts[1]
			if _, ok := d.Dataplane.IPSetMembers[name]; !ok {
				return []byte("set doesn't exist"), &exec.ExitError{}
			}
			delete(d.Dataplane.IPSetMembers, name)
			log.WithField("setName", name).Info("Set destroyed")
		case "add":
			Expect(len(parts)).To(Equal(3))
			name := parts[1]
			newMember := parts[2]
			logCxt := log.WithField("setName", name)
			if currentMembers, ok := d.Dataplane.IPSetMembers[name]; !ok {
				return []byte("set doesn't exist"), &exec.ExitError{}
			} else {
				if currentMembers.Contains(newMember) {
					d.Dataplane.TriedToAddExistent = true
					logCxt.Warn("Add of existing member")
					return []byte("member already exists"), &exec.ExitError{}
				}
				currentMembers.Add(newMember)
				logCxt.WithField("member", newMember).Info("Member added")
			}
		case "del":
			Expect(len(parts)).To(Equal(3))
			name := parts[1]
			newMember := parts[2]
			logCxt := log.WithField("setName", name)
			if currentMembers, ok := d.Dataplane.IPSetMembers[name]; !ok {
				return []byte("set doesn't exist"), &exec.ExitError{}
			} else {
				if !currentMembers.Contains(newMember) {
					d.Dataplane.TriedToDeleteNonExistent = true
					logCxt.Warn("Delete of non-existent member")
					return []byte("member doesn't exist"), &exec.ExitError{}
				}
				currentMembers.Discard(newMember)
				logCxt.WithField("member", newMember).Info("Member deleted")
			}
		case "swap":
			Expect(len(parts)).To(Equal(3))
			name1 := parts[1]
			name2 := parts[2]

			log.WithFields(log.Fields{
				"name1": name1,
				"name2": name2,
			}).Info("Swapping IP sets")

			if set1, ok := d.Dataplane.IPSetMembers[name1]; !ok {
				log.WithField("name", name1).Warn("IP set doesn't exist")
				return []byte("set doesn't exist"), &exec.ExitError{}
			} else if set2, ok := d.Dataplane.IPSetMembers[name2]; !ok {
				log.WithField("name", name2).Warn("IP set doesn't exist")
				return []byte("set doesn't exist"), &exec.ExitError{}
			} else {
				d.Dataplane.IPSetMembers[name1] = set2
				d.Dataplane.IPSetMembers[name2] = set1

				meta1 := d.Dataplane.IPSetMetadata[name1]
				meta2 := d.Dataplane.IPSetMetadata[name2]
				d.Dataplane.IPSetMetadata[name1] = meta2
				d.Dataplane.IPSetMetadata[name2] = meta1
			}
		case "COMMIT":
			commitSeen = true
		default:
			Fail("Unknown action: " + line)
		}
	}
	Expect(commitSeen).To(BeTrue())
	return nil, nil
}

type setMetadata struct {
	Name    string
	Family  IPFamily
	Type    IPSetType
	MaxSize int
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
	if d.Dataplane.FailNextDestroy {
		d.Dataplane.FailNextDestroy = false
		return nil, &exec.ExitError{}
	}
	if _, ok := d.Dataplane.IPSetMembers[d.SetName]; ok {
		// IP set exists.
		delete(d.Dataplane.IPSetMembers, d.SetName)
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
