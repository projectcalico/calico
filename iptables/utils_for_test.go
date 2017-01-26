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
	. "github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/set"
	"io"
	"strconv"
	"strings"
	"time"
)

// This file contains shared test infrastructure for testing the iptables package.

func newMockDataplane(table string, chains map[string][]string) *mockDataplane {
	return &mockDataplane{
		Table:         table,
		Chains:        chains,
		FlushedChains: set.New(),
		ChainMods:     set.New(),
		DeletedChains: set.New(),
	}
}

type chainMod struct {
	name    string
	ruleNum int
}

type mockDataplane struct {
	Table           string
	Chains          map[string][]string
	FlushedChains   set.Set
	ChainMods       set.Set
	DeletedChains   set.Set
	Cmds            []CmdIface
	FailNextRestore bool
	FailAllRestores bool
	OnPreRestore    func()
	FailNextSave    bool
	FailAllSaves    bool
	CumulativeSleep time.Duration
}

func (d *mockDataplane) newCmd(name string, arg ...string) CmdIface {
	log.WithFields(log.Fields{
		"name":            name,
		"args":            arg,
		"FailNextRestore": d.FailNextRestore,
		"FailNextSave":    d.FailNextSave,
		"FailAllRestores": d.FailAllRestores,
		"FailAllSaves":    d.FailAllSaves,
	}).Info("Simulating new command.")

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

func (d *mockDataplane) sleep(duration time.Duration) {
	d.CumulativeSleep += duration
}

func (d *mockDataplane) ChainFlushed(chainName string) bool {
	return d.FlushedChains.Contains(chainName)
}

func (d *mockDataplane) RuleTouched(chainName string, ruleNum int) bool {
	if d.ChainFlushed(chainName) {
		// Whole chain blown away.
		return true
	}
	return d.ChainMods.Contains(chainMod{name: chainName, ruleNum: ruleNum})
}

type restoreCmd struct {
	Dataplane     *mockDataplane
	Stdin         *bytes.Buffer
	CapturedStdin string
	Stdout        io.Writer
	Stderr        io.Writer
}

func (d *restoreCmd) SetStdin(r io.Reader) {
	d.Stdin = r.(*bytes.Buffer)
	d.CapturedStdin = d.Stdin.String()
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

func (d *restoreCmd) String() string {
	return fmt.Sprintf("restoreCmd %#v", d.CapturedStdin)
}

func (d *restoreCmd) Run() error {
	log.Info("Running simulated iptables-restore")
	// Get the input.
	var buf bytes.Buffer
	_, err := buf.ReadFrom(d.Stdin)
	Expect(err).NotTo(HaveOccurred())
	input := buf.String()

	if d.Dataplane.OnPreRestore != nil {
		log.Warn("OnPreRestore set, calling it")
		d.Dataplane.OnPreRestore()
		d.Dataplane.OnPreRestore = nil
	}
	if d.Dataplane.FailNextRestore {
		log.Warn("Simulating an iptables-restore failure")
		d.Dataplane.FailNextRestore = false
		return errors.New("Simulated failure")
	}
	if d.Dataplane.FailAllRestores {
		log.Warn("Simulating an iptables-restore failure")
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
			d.Dataplane.FlushedChains.Add(chainName)
			continue
		}

		parts := strings.Split(line, " ")
		action := parts[0]
		var chainName string
		switch action {
		case "-A", "--append":
			chainName = parts[1]
			rest := strings.Join(parts[2:], " ")
			Expect(chains[chainName]).NotTo(BeNil(), "Append to unknown chain: "+chainName)
			chains[chainName] = append(chains[chainName], rest)
			d.Dataplane.ChainMods.Add(chainMod{name: chainName, ruleNum: len(chains[chainName])})
		case "-I", "--insert":
			chainName = parts[1]
			rest := strings.Join(parts[2:], " ")
			Expect(chains[chainName]).NotTo(BeNil(), "Insert to unknown chain: "+chainName)
			chains[chainName] = append(chains[chainName], "") // Make room
			chain := chains[chainName]
			for i := len(chain) - 1; i > 0; i-- {
				chain[i] = chain[i-1]
			}
			chain[0] = rest
			d.Dataplane.ChainMods.Add(chainMod{name: chainName, ruleNum: 1})
		case "-R", "--replace":
			chainName = parts[1]
			ruleNum, err := strconv.Atoi(parts[2]) // 1-indexed position of rule.
			Expect(err).NotTo(HaveOccurred())
			rest := strings.Join(parts[3:], " ")
			ruleIdx := ruleNum - 1 // 0-indexed array index of rule.
			chain := chains[chainName]
			Expect(len(chain)).To(BeNumerically(">", ruleIdx), "Replace of non-existent rule")
			chain[ruleIdx] = rest
			d.Dataplane.ChainMods.Add(chainMod{name: chainName, ruleNum: ruleNum})
		case "-D", "--delete":
			chainName = parts[1]
			Expect(len(parts)).To(Equal(3), "--delete only expects two arguments")
			ruleNum, err := strconv.Atoi(parts[2]) // 1-indexed position of rule.
			Expect(err).NotTo(HaveOccurred())
			ruleIdx := ruleNum - 1 // 0-indexed array index of rule.
			chain := chains[chainName]
			Expect(len(chain)).To(BeNumerically(">", ruleIdx), "Delete of non-existent rule")
			for i := ruleIdx; i < len(chain)-1; i++ {
				chain[i] = chain[i+1]
			}
			chains[chainName] = chain[:len(chain)-1]
			d.Dataplane.ChainMods.Add(chainMod{name: chainName, ruleNum: ruleNum})
		case "-X", "--delete-chain":
			chainName = parts[1]
			Expect(len(parts)).To(Equal(2), "--delete-chain only has one argument")
			Expect(chains[chainName]).To(Equal([]string{}), "Only empty chains can be deleted")
			delete(chains, chainName)
			d.Dataplane.DeletedChains.Add(chainName)
		default:
			Fail("Unknown action: " + action)
		}
		log.Debugf("Updated chain '%s' (len=%v); new contents:\n\t%v",
			chainName, len(chains[chainName]), strings.Join(chains[chainName], "\n\t"))
	}
	Expect(commitSeen).To(BeTrue())
	return nil
}

type saveCmd struct {
	Dataplane *mockDataplane
}

func (d *saveCmd) String() string {
	return "saveCmd"
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
	if d.Dataplane.FailAllSaves {
		return nil, errors.New("Simulated failure")
	}
	var buf bytes.Buffer

	buf.WriteString("# generated by dummy iptables-save\n")
	buf.WriteString(fmt.Sprintf("*%s\n", d.Dataplane.Table))
	for chainName := range d.Dataplane.Chains {
		buf.WriteString(fmt.Sprintf(":%s - [123:456]\n", chainName))
	}

	for chainName, chain := range d.Dataplane.Chains {
		for _, rule := range chain {
			buf.WriteString(fmt.Sprintf("-A %s %s\n", chainName, rule))
		}
	}
	buf.WriteString("COMMIT\n")
	buf.WriteString("# completed\n")

	log.Debugf("Calculated save output:\n%v", buf.String())

	return buf.Bytes(), nil
}

func (d *saveCmd) Run() error {
	return errors.New("Not implemented")
}
