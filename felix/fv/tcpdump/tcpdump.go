// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

package tcpdump

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"

	"sync"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"strings"

	"time"

	"github.com/onsi/ginkgo"

	"github.com/projectcalico/calico/felix/fv/utils"
)

// Attach use if tcpdump is available in the container
func Attach(containerName, netns, iface string) *TCPDump {
	t := &TCPDump{
		exe:              "docker",
		logEnabled:       true,
		contName:         containerName,
		matchers:         map[string]*tcpDumpMatcher{},
		listeningStarted: make(chan struct{}),
	}

	t.args = []string{"exec", t.contName}
	if netns != "" {
		t.args = append(t.args, "ip", "netns", "exec", netns)
	}
	t.args = append(t.args, "tcpdump", "-nli", iface)

	t.logString = containerName
	if netns != "" {
		t.logString += ":" + netns
	}

	return t
}

// AttachUnavailable use if tcpdump is not available in the container
func AttachUnavailable(containerID, iface string) *TCPDump {
	containerName := "tcpdump-" + containerID + "-" + iface
	t := Attach(containerName, "", iface)

	t.args = []string{"run",
		"--rm",
		"--name", containerName,
		fmt.Sprintf("--network=container:%s", containerID),
		"corfr/tcpdump", "-nli", iface}

	return t
}

type stringMatcher interface {
	MatchString(string) bool
}

type tcpDumpMatcher struct {
	regex stringMatcher
	count int
}

type TCPDump struct {
	lock sync.Mutex

	logEnabled       bool
	contName         string
	exe              string
	args             []string
	logString        string
	cmd              *exec.Cmd
	out, err         io.ReadCloser
	listeningStarted chan struct{}

	matchers map[string]*tcpDumpMatcher
}

func (t *TCPDump) SetLogEnabled(logEnabled bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.logEnabled = logEnabled
}

func (t *TCPDump) SetLogString(str string) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.logString = str
}

func (t *TCPDump) AddMatcher(name string, s stringMatcher) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.matchers[name] = &tcpDumpMatcher{
		regex: s,
	}
}

func (t *TCPDump) MatchCount(name string) int {
	t.lock.Lock()
	defer t.lock.Unlock()

	c := t.matchers[name].count
	logrus.Infof("[%s] Match count for %s is %v", t.contName, name, c)
	return c
}

func (t *TCPDump) MatchCountFn(name string) func() int {
	return func() int {
		return t.MatchCount(name)
	}
}

func (t *TCPDump) ResetCount(name string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.matchers[name].count = 0
	logrus.Infof("[%s] Reset count for %s", t.contName, name)
}

func (t *TCPDump) Start(expr ...string) {
	args := append(t.args, expr...)
	t.cmd = utils.Command(t.exe, args...)
	var err error
	t.out, err = t.cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())

	t.err, err = t.cmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())

	go t.readStdout()
	go t.readStderr()

	err = t.cmd.Start()

	select {
	case <-t.listeningStarted:
	case <-time.After(60 * time.Second):
		ginkgo.Fail("Failed to start tcpdump: it never reported that it was listening")
	}

	Expect(err).NotTo(HaveOccurred())
}

func (t *TCPDump) Stop() {
	var err error
	if t.args[0] == "run" {
		err = exec.Command("docker", "stop", t.contName).Run()
	} else {
		err = t.cmd.Process.Kill()
	}
	if err != nil {
		logrus.WithError(err).Error("Failed to kill tcpdump; maybe it failed to start?")
	}
}

func (t *TCPDump) readStdout() {
	s := bufio.NewScanner(t.out)
	for s.Scan() {
		line := s.Text()

		t.lock.Lock()
		logEnabled := t.logEnabled
		t.lock.Unlock()

		if logEnabled {
			logrus.Infof("[%s] %s", t.contName, line)
		}
		t.lock.Lock()
		for _, m := range t.matchers {
			if m.regex.MatchString(line) {
				m.count++
			}
		}
		t.lock.Unlock()
	}
	logrus.WithError(s.Err()).Info("TCPDump stdout finished")
}

func (t *TCPDump) readStderr() {
	defer ginkgo.GinkgoRecover()

	s := bufio.NewScanner(t.err)
	closedChan := false
	safeClose := func() {
		if !closedChan {
			close(t.listeningStarted)
			closedChan = true
		}
	}

	listening := false

	defer func() {
		Expect(listening).To(BeTrue())
		safeClose()
	}()

	for s.Scan() {
		line := s.Text()
		logrus.Infof("[%s] ERR: %s", t.contName, line)
		if strings.Contains(line, "listening") {
			listening = true
			safeClose()
		}
	}
	logrus.WithError(s.Err()).Info("TCPDump stderr finished")
}
