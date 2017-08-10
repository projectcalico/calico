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
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"bufio"

	"time"

	"bytes"
	"regexp"

	. "github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/libcalico-go/lib/set"
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
	IPSetMembers      map[string]set.Set
	IPSetMetadata     map[string]setMetadata
	Cmds              []CmdIface
	CmdNames          []string
	FailAllRestores   bool
	FailAllLists      bool
	ListOpFailures    []string
	RestoreOpFailures []string
	FailNextDestroy   bool

	// Record when various (expected) error cases are hit.
	TriedToDeleteNonExistent bool
	TriedToAddExistent       bool

	CumulativeSleep time.Duration
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
			resultC:   make(chan error),
		}
	case "destroy":
		Expect(len(arg)).To(Equal(2))
		name := arg[1]
		cmd = &destroyCmd{
			Dataplane: d,
			SetName:   name,
		}
	case "list":
		Expect(len(arg)).To(Equal(1))
		cmd = &listCmd{
			Dataplane: d,
			resultC:   make(chan error),
		}
	default:
		Fail(fmt.Sprintf("Unexpected command %v", arg))
	}

	d.Cmds = append(d.Cmds, cmd)
	d.CmdNames = append(d.CmdNames, arg[0])

	return cmd
}

func (d *mockDataplane) sleep(t time.Duration) {
	d.CumulativeSleep += t
}

func (d *mockDataplane) popListOpFailure(failType string) bool {
	if len(d.ListOpFailures) > 0 && d.ListOpFailures[0] == failType {
		log.WithField("failureType", failType).Warn("About to simulate list failure")
		d.ListOpFailures = d.ListOpFailures[1:]
		return true
	}
	return false
}

func (d *mockDataplane) popRestoreFailure(failType string) bool {
	if len(d.RestoreOpFailures) > 0 && d.RestoreOpFailures[0] == failType {
		log.WithField("failureType", failType).Warn("About to simulate restore failure")
		d.RestoreOpFailures = d.RestoreOpFailures[1:]
		return true
	}
	return false
}

type restoreCmd struct {
	Dataplane *mockDataplane
	SetName   string
	Stdin     io.Reader
	Stderr    io.Writer
	Stdout    io.Writer
	resultC   chan error
}

func (c *restoreCmd) SetStdin(r io.Reader) {
	c.Stdin = r
}

func (c *restoreCmd) SetStderr(r io.Writer) {
	c.Stderr = r
}

func (c *restoreCmd) SetStdout(r io.Writer) {
	c.Stdout = r
}

func (c *restoreCmd) StdinPipe() (WriteCloserFlusher, error) {
	log.Info("Restore command asked for a stdin pipe")
	if c.Dataplane.popRestoreFailure("pipe") {
		log.Warn("Simulating failure to create pipe")
		return nil, transientFailure
	}
	if c.Dataplane.popRestoreFailure("write") {
		log.Warn("Returning a bad pipe that will fail writes")
		return &badPipe{}, nil
	}
	if c.Dataplane.popRestoreFailure("write-ip") {
		log.Warn("Returning a bad pipe that will fail when writing an IP")
		return &badPipe{
			FirstWriteFailRegexp: regexp.MustCompile(`\s*\d+\.\d+\.\d+\.\d+\s*`),
		}, nil
	}
	if c.Dataplane.popRestoreFailure("close") {
		log.Warn("Returning a bad pipe that will fail when closedP")
		return &badPipe{
			CloseFail: true,
		}, nil
	}
	pipeR, pipeW := io.Pipe()
	c.Stdin = pipeR
	buf := bufio.NewWriter(pipeW)
	return &BufferedCloser{
		BufWriter: buf,
		Closer:    pipeW,
	}, nil
}

func (c *restoreCmd) StdoutPipe() (io.ReadCloser, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (c *restoreCmd) Start() error {
	log.Info("Restore command started")
	if c.Dataplane.popRestoreFailure("start") {
		return transientFailure
	}
	go c.main()
	return nil
}

func (c *restoreCmd) Wait() error {
	return <-c.resultC
}

func (c *restoreCmd) Output() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (c *restoreCmd) main() {
	defer GinkgoRecover()

	var result error

	defer func() {
		log.WithField("procResult", result).Info("restore command main is exiting")
		if c.Stdin != nil && result != nil {
			c.Stdin.(io.Closer).Close()
		}
		c.resultC <- result
	}()

	if c.Dataplane.FailAllRestores {
		log.Warn("Restore command permanent failure")
		result = permanentFailure
		return
	}

	if c.Dataplane.popRestoreFailure("pre-update") {
		log.Warn("Restore command simulating pre-update failure")
		result = transientFailure
		return
	}

	if c.Stdin == nil {
		log.Warn("Restore command has no stdin")
		result = transientFailure
		return
	}

	// Process it line by line.
	scanner := bufio.NewScanner(c.Stdin)
	commitSeen := false
	i := 0
	for scanner.Scan() {
		line := scanner.Text()
		i++
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

			if _, ok := c.Dataplane.IPSetMembers[name]; ok {
				c.Stderr.Write([]byte("set exists"))
				result = &exec.ExitError{}
				return
			}

			c.Dataplane.IPSetMembers[name] = set.New()
			c.Dataplane.IPSetMetadata[name] = setMetadata
		case "destroy":
			Expect(len(parts)).To(Equal(2))
			name := parts[1]
			if _, ok := c.Dataplane.IPSetMembers[name]; !ok {
				c.Stderr.Write([]byte("set doesn't exist"))
				result = &exec.ExitError{}
				return
			}
			delete(c.Dataplane.IPSetMembers, name)
			log.WithField("setName", name).Info("Set destroyed")
		case "add":
			Expect(len(parts)).To(Equal(3))
			name := parts[1]
			newMember := parts[2]
			logCxt := log.WithField("setName", name)
			if currentMembers, ok := c.Dataplane.IPSetMembers[name]; !ok {
				c.Stderr.Write([]byte("set doesn't exist"))
				result = &exec.ExitError{}
				return
			} else {
				if currentMembers.Contains(newMember) {
					c.Dataplane.TriedToAddExistent = true
					logCxt.Warn("Add of existing member")
					c.Stderr.Write([]byte("member already exists"))
					result = &exec.ExitError{}
					return
				}
				currentMembers.Add(newMember)
				logCxt.WithField("member", newMember).Info("Member added")
			}
		case "del":
			Expect(len(parts)).To(Equal(4))
			name := parts[1]
			newMember := parts[2]
			Expect(parts[3]).To(Equal("--exist"))
			logCxt := log.WithField("setName", name)
			if currentMembers, ok := c.Dataplane.IPSetMembers[name]; !ok {
				c.Stderr.Write([]byte("set doesn't exist"))
				result = &exec.ExitError{}
				return
			} else {
				existing := currentMembers.Contains(newMember)
				if !existing {
					c.Dataplane.TriedToDeleteNonExistent = true
				}
				currentMembers.Discard(newMember)
				logCxt.WithFields(log.Fields{
					"member":        newMember,
					"existedBefore": existing},
				).Info("Member deleted")
			}
			if c.Dataplane.popRestoreFailure("post-del") {
				log.Warn("Simulating a failure after first deletion.")
				result = transientFailure
				return
			}
		case "swap":
			Expect(len(parts)).To(Equal(3))
			name1 := parts[1]
			name2 := parts[2]

			log.WithFields(log.Fields{
				"name1": name1,
				"name2": name2,
			}).Info("Swapping IP sets")

			if set1, ok := c.Dataplane.IPSetMembers[name1]; !ok {
				log.WithField("name", name1).Warn("IP set doesn't exist")
				c.Stderr.Write([]byte("set doesn't exist"))
				result = &exec.ExitError{}
				return
			} else if set2, ok := c.Dataplane.IPSetMembers[name2]; !ok {
				log.WithField("name", name2).Warn("IP set doesn't exist")
				c.Stderr.Write([]byte("set doesn't exist"))
				result = &exec.ExitError{}
				return
			} else {
				c.Dataplane.IPSetMembers[name1] = set2
				c.Dataplane.IPSetMembers[name2] = set1

				meta1 := c.Dataplane.IPSetMetadata[name1]
				meta2 := c.Dataplane.IPSetMetadata[name2]
				c.Dataplane.IPSetMetadata[name1] = meta2
				c.Dataplane.IPSetMetadata[name2] = meta1
			}
		case "COMMIT":
			commitSeen = true
		default:
			Fail("Unknown action: " + line)
		}
	}
	Expect(commitSeen).To(BeTrue())

	if c.Dataplane.popRestoreFailure("post-update") {
		result = transientFailure
		return
	}
}

func (d *restoreCmd) CombinedOutput() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
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

func (d *destroyCmd) SetStderr(r io.Writer) {
	Fail("not implemented")
}

func (d *destroyCmd) SetStdout(r io.Writer) {
	Fail("not implemented")
}

func (d *destroyCmd) StdinPipe() (WriteCloserFlusher, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (d *destroyCmd) StdoutPipe() (io.ReadCloser, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (d *destroyCmd) Start() error {
	return nil
}

func (d *destroyCmd) Wait() error {
	return nil
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
		d.Dataplane.TriedToDeleteNonExistent = true
		return []byte("ipset v6.29: The set with the given name does not exist"),
			&exec.ExitError{} // No need to fill, error not parsed by caller.
	}
}

type listCmd struct {
	Dataplane *mockDataplane
	SetName   string
	Stdout    *io.PipeWriter
	resultC   chan error
}

func (c *listCmd) SetStdin(_ io.Reader) {
	Fail("listNamesCmd expects no input")
}

func (c *listCmd) SetStderr(r io.Writer) {

}

func (c *listCmd) SetStdout(r io.Writer) {
	Fail("not implemented")
}

func (c *listCmd) StdinPipe() (WriteCloserFlusher, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (c *listCmd) StdoutPipe() (io.ReadCloser, error) {
	if c.Dataplane.popListOpFailure("pipe") {
		// Fail to create the pipe.
		return nil, transientFailure
	}
	if c.Dataplane.popListOpFailure("read") {
		// Fail all reads.
		return &badPipe{}, nil
	}
	if c.Dataplane.popListOpFailure("read-member") {
		// Fail in the middle of reading the Members block.
		return &badPipe{
			data: []byte(
				"Name: " + v4MainIPSetName + "\n" +
					"Members:\n10.0.0.1\n"),
		}, nil
	}
	if c.Dataplane.popListOpFailure("close") {
		// Fail at close time.
		return &badPipe{
			ReadError: io.EOF,
			CloseFail: true,
		}, nil
	}
	pipeR, pipeW := io.Pipe()
	c.Stdout = pipeW
	return pipeR, nil
}

type badPipe struct {
	data                 []byte
	CloseFail            bool
	FirstWriteFailRegexp *regexp.Regexp
	ReadError            error
}

func (pipe *badPipe) Read(p []byte) (n int, err error) {
	if pipe.data != nil {
		log.Info("Bad pipe returning data")
		n = copy(p, pipe.data)
		if n == len(pipe.data) {
			pipe.data = nil
		} else {
			pipe.data = pipe.data[n:]
		}
		return
	}
	log.Info("Bad pipe returning read error")
	if pipe.ReadError != nil {
		return 0, pipe.ReadError
	}
	return 0, transientFailure
}

func (p *badPipe) Write(x []byte) (n int, err error) {
	if p.FirstWriteFailRegexp != nil {
		// Delay failure until we hit the regex.
		log.WithField("data", string(x)).Debug("Bad pipe write input")
		if !p.FirstWriteFailRegexp.Match(x) {
			return len(x), nil
		}
		log.Info("Bad pipe FirstWriteFailRegexp matches")
		p.FirstWriteFailRegexp = nil
	}
	log.Info("Bad pipe returning write error")
	return 0, transientFailure
}

func (p *badPipe) Flush() error {
	// Mock out flush so we see every write.
	return nil
}

func (p *badPipe) Close() error {
	if p.CloseFail {
		return transientFailure
	}
	return nil
}

func (c *listCmd) Start() error {
	if c.Dataplane.popListOpFailure("start") {
		return transientFailure
	}
	go c.main()
	return nil
}

func (c *listCmd) Wait() error {
	log.Info("Waiting for list command to finish.")
	return <-c.resultC
}

func (c *listCmd) Output() ([]byte, error) {
	if c.Dataplane.FailAllLists {
		return nil, permanentFailure
	}
	var buf bytes.Buffer
	pipe, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	go c.main()
	_, err = io.Copy(&buf, pipe)
	return buf.Bytes(), err
}

func (c *listCmd) CombinedOutput() ([]byte, error) {
	Fail("Not implemented")
	return nil, errors.New("Not implemented")
}

func (c *listCmd) main() {
	defer GinkgoRecover()

	var result error

	defer func() {
		log.WithField("result", result).Info("list command main exiting")
		if c.Stdout != nil {
			c.Stdout.Close()
		}
		c.resultC <- result
	}()

	if c.Dataplane.FailAllLists {
		log.Info("Simulating persistent failure of ipset list")
		result = permanentFailure
		return
	}

	if c.Dataplane.popListOpFailure("force-good-rc") {
		log.Info("Forcing a good RC")
		return
	}

	if c.Stdout == nil {
		log.Info("stdout is nil, must be testing a failure scenario")
		result = transientFailure
		return
	}

	if c.Dataplane.popListOpFailure("rc") {
		log.Info("Forcing a bad RC")
		result = transientFailure
		return
	}

	first := true
	for setName, members := range c.Dataplane.IPSetMembers {
		if !first {
			fmt.Fprint(c.Stdout, "\n")
		}
		fmt.Fprintf(c.Stdout, "Name: %s\n", setName)
		fmt.Fprint(c.Stdout, "Field: foobar\n") // Dummy field, should get ignored.
		fmt.Fprint(c.Stdout, "Members:\n")
		members.Iter(func(member interface{}) error {
			fmt.Fprintf(c.Stdout, "%s\n", member)
			return nil
		})
		first = false
	}
}
