// +build fvtests

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

package fv_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/fv/utils"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("with running container", func() {
	var containerIdx int
	var containerName string
	var felixCmd *exec.Cmd

	cmdInContainer := func(cmd ...string) *exec.Cmd {
		arg := []string{"exec", containerName}
		arg = append(arg, cmd...)
		return utils.Command("docker", arg...)
	}

	BeforeEach(func() {
		containerName = fmt.Sprintf("felix-fv-%d-%d", os.Getpid(), containerIdx)
		containerIdx++
		myDir, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		log.WithFields(log.Fields{
			"name":  containerName,
			"myDir": myDir,
		}).Info("Starting a Felix container")
		// Run a felix container.  The tests in this file don't actually rely on Felix
		// but the calico/felix container has all the iptables dependencies we need to
		// check the lock behaviour.  Note: we don't map the host's iptables lock into the
		// container so the scope of the lock is limited to the container.
		felixCmd = utils.Command("docker", "run",
			"--rm",
			"--name", containerName,
			"-v", fmt.Sprintf("%s/..:/codebase", myDir),
			"--privileged",
			"calico/felix")
		err = felixCmd.Start()
		Expect(err).NotTo(HaveOccurred())

		log.Info("Waiting for container to be listed in docker ps")
		start := time.Now()
		for {
			cmd := utils.Command("docker", "ps")
			out, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			if strings.Contains(string(out), containerName) {
				break
			}
			if time.Since(start) > 10*time.Second {
				log.Panic("Timed out waiting for container to be listed.")
			}
		}
	})
	AfterEach(func() {
		// Send an interrupt to ensure that docker gracefully shuts down the container.
		// If we kill the docker process then it detaches the container.
		log.Info("Stopping Felix container")
		felixCmd.Process.Signal(os.Interrupt)
	})

	Describe("with the lock being held for 2s", func() {
		var lockCmd *exec.Cmd
		BeforeEach(func() {
			// Start the iptables-locker, which is a simple test app that locks
			// the iptables lock and then releases it after a timeout.
			log.Info("Starting iptables-locker")
			lockCmd = cmdInContainer("/codebase/bin/iptables-locker", "2s")
			stdErr, err := lockCmd.StderrPipe()
			Expect(err).NotTo(HaveOccurred())
			lockCmd.Start()

			// Wait for the iptables-locker to tell us that it actually acquired the
			// lock.
			log.Info("Waiting for iptables-locker to acquire lock")
			scanner := bufio.NewScanner(stdErr)
			scanResult := scanner.Scan()
			if !scanResult {
				log.WithError(scanner.Err()).Warning("Scan failed")
			}
			Expect(scanResult).To(BeTrue())
			Expect(scanner.Text()).To(Equal("LOCKED"))
			Expect(scanner.Err()).NotTo(HaveOccurred())
			log.Info("iptables-locker acquired lock")
		})

		It("iptables should fail to get the lock in 1s", func() {
			iptCmd := cmdInContainer("iptables", "-w", "1", "-A", "FORWARD")
			out, err := iptCmd.CombinedOutput()
			Expect(string(out)).To(ContainSubstring("Stopped waiting"))
			Expect(err).To(HaveOccurred())
		})

		It("iptables should succeed in getting the lock after 3s", func() {
			iptCmd := cmdInContainer("iptables", "-w", "3", "-A", "FORWARD")
			out, err := iptCmd.CombinedOutput()
			log.Infof("iptables output='%s'", out)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if lockCmd != nil {
				log.Info("waiting for iptables-locker to finish")
				err := lockCmd.Wait()
				Expect(err).NotTo(HaveOccurred())
			}
		})
	})
})
