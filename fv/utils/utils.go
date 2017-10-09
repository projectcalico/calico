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

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	log "github.com/sirupsen/logrus"
)

func Run(command string, args ...string) {
	_ = run(true, command, args...)
}

func RunMayFail(command string, args ...string) error {
	return run(false, command, args...)
}

var currentTestOutput = []string{}

func run(checkNoError bool, command string, args ...string) error {
	outputBytes, err := Command(command, args...).CombinedOutput()
	currentTestOutput = append(currentTestOutput, fmt.Sprintf("Command: %v %v\n", command, args))
	currentTestOutput = append(currentTestOutput, string(outputBytes))
	if err != nil {
		log.WithFields(log.Fields{
			"command": command,
			"args":    args}).WithError(err).Warning("Command failed")
	}
	if checkNoError {
		Expect(err).NotTo(HaveOccurred())
	}
	return err
}

var _ = BeforeEach(func() {
	currentTestOutput = []string{}
})

var _ = AfterEach(func() {
	if CurrentGinkgoTestDescription().Failed {
		os.Stdout.WriteString("\n===== begin output from failed test =====\n")
		for _, output := range currentTestOutput {
			os.Stdout.WriteString(output)
		}
		os.Stdout.WriteString("===== end output from failed test =====\n\n")
	}
})

func RunCommand(command string, args ...string) error {
	cmd := Command(command, args...)
	log.Infof("Running '%s %s'", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	log.Infof("output: %v", string(output))
	return err
}

func Command(name string, args ...string) *exec.Cmd {
	log.WithFields(log.Fields{
		"command":     name,
		"commandArgs": args,
	}).Info("Creating Command.")

	return exec.Command(name, args...)
}

func GetEtcdClient(etcdIP string) *client.Client {
	client, err := client.New(api.CalicoAPIConfig{
		Spec: api.CalicoAPIConfigSpec{
			DatastoreType: api.EtcdV2,
			EtcdConfig: api.EtcdConfig{
				EtcdEndpoints: "http://" + etcdIP + ":2379",
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	return client
}
