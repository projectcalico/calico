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

package iptables_test

import (
	"bytes"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/felix/go/felix/iptables"
	"io"
	"strconv"
	"strings"
)

// This file contains shared test infrastructure for testing the iptables package.

func newMockDataplane(table string, chains map[string][]string) *mockDataplane {
	return &mockDataplane{
		Table:  table,
		Chains: chains,
	}
}

type mockDataplane struct {
	Table           string
	Chains          map[string][]string
	Cmds            []CmdIface
	FailNextRestore bool
	FailNextSave    bool
}

func (d *mockDataplane) newCmd(name string, arg ...string) CmdIface {
	var cmd CmdIface

	switch name {
	case "iptables-restore", "ip6tables-restore":
		Expect(arg).To(Equal([]string{"--noflush", "--verbose"}))
		cmd = &restoreCmd{
			Dataplane: d,
		}
	case "iptables-save", "ip6tables-save":
		Expect(arg).To(Equal([]string{"-t", d.Table}))
		cmd = &saveCmd{
			Dataplane: d,
		}
	default:
		Fail(fmt.Sprintf("Unexpected command %v", name))
	}

	d.Cmds = append(d.Cmds, cmd)

	return cmd
}

type restoreCmd struct {
	Dataplane *mockDataplane
	SetName   string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

func (d *restoreCmd) SetStdin(r io.Reader) {
	d.Stdin = r
}

func (d *restoreCmd) SetStdout(w io.Writer) {
	d.Stdout = w
}

func (d *restoreCmd) SetStderr(w io.Writer) {
	d.Stderr = w
}

func (d *restoreCmd) Output() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (d *restoreCmd) Run() error {
	// Get the input.
	var buf bytes.Buffer
	_, err := buf.ReadFrom(d.Stdin)
	Expect(err).NotTo(HaveOccurred())
	input := buf.String()

	if d.Dataplane.FailNextRestore {
		d.Dataplane.FailNextRestore = false
		return errors.New("Simulated failure")
	}

	// Process it line by line.
	lines := strings.Split(input, "\n")
	commitSeen := false
	tableSeen := false

	for i, line := range lines {
		log.WithFields(log.Fields{"line": line, "lineNum": i + 1}).Info("Parsing line")
		if strings.Trim(line, " \n") == "" {
			// Ignore empty lines (including final trailing return).
			continue
		}
		if strings.HasPrefix(line, "#") {
			// Ignore comments.
			continue
		}
		if strings.HasPrefix(line, "*") {
			// Start of a table.
			Expect(line[1:]).To(Equal(d.Dataplane.Table))
			tableSeen = true
			continue
		}
		Expect(tableSeen).To(BeTrue(), "No *table stanza before starting input")
		Expect(commitSeen).To(BeFalse(), "Unexpected line after COMMIT")
		if line == "COMMIT" {
			commitSeen = true
			continue
		}

		chains := d.Dataplane.Chains

		if strings.HasPrefix(line, ":") {
			// Chain forward-ref, creates and flushes the chain as needed.
			parts := strings.Split(line[1:], " ")
			chainName := parts[0]
			Expect(parts[1:]).To(Equal([]string{"-", "-"}))
			chains[chainName] = []string{}
			continue
		}

		parts := strings.Split(line, " ")
		action := parts[0]
		switch action {
		case "-A", "--append":
			chainName := parts[1]
			rest := strings.Join(parts[2:], " ")
			Expect(chains[chainName]).NotTo(BeNil(), "Append to unknown chain: "+chainName)
			chains[chainName] = append(chains[chainName], rest)
		case "-I", "--insert":
			chainName := parts[1]
			rest := strings.Join(parts[2:], " ")
			Expect(chains[chainName]).NotTo(BeNil(), "Insert to unknown chain: "+chainName)
			chains[chainName] = append(chains[chainName], "") // Make room
			chain := chains[chainName]
			for i, line := range chain {
				if i >= len(chain)-1 {
					break
				}
				chain[i+1] = line
			}
			chain[0] = rest
		case "-R", "--replace":
			chainName := parts[1]
			ruleNum, err := strconv.Atoi(parts[2]) // 1-indexed position of rule.
			Expect(err).NotTo(HaveOccurred())
			rest := strings.Join(parts[3:], " ")
			ruleIdx := ruleNum - 1 // 0-indexed array index of rule.
			chain := chains[chainName]
			Expect(len(chain)).To(BeNumerically(">", ruleIdx), "Replace of non-existent rule")
			chain[ruleIdx] = rest
		default:
			Fail("Unknown action: " + action)
		}
	}
	Expect(commitSeen).To(BeTrue())
	return nil
}

type saveCmd struct {
	Dataplane *mockDataplane
	SetName   string
}

func (d *saveCmd) SetStdin(r io.Reader) {
	Fail("Not implemented")
}

func (d *saveCmd) SetStdout(w io.Writer) {
	Fail("Not implemented")
}

func (d *saveCmd) SetStderr(w io.Writer) {
	Fail("Not implemented")
}

func (d *saveCmd) Output() ([]byte, error) {

	if d.Dataplane.FailNextSave {
		d.Dataplane.FailNextSave = false
		return nil, errors.New("Simulated failure")
	}

	return nil, nil
}

func (d *saveCmd) Run() error {
	return errors.New("Not implemented")
}
