// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/selector"

	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/fv/connectivity"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/rules"
)

type EnvConfig struct {
	FelixImage   string `default:"calico/felix:latest"`
	EtcdImage    string `default:"quay.io/coreos/etcd"`
	K8sImage     string `default:"gcr.io/google_containers/hyperkube-amd64:v1.10.4"`
	TyphaImage   string `default:"calico/typha:latest"` // Note: this is overridden in the Makefile!
	BusyboxImage string `default:"busybox:latest"`
}

var Config EnvConfig

func init() {
	err := envconfig.Process("fv", &Config)
	if err != nil {
		panic(err)
	}
	log.WithField("config", Config).Info("Loaded config")
}

var Ctx = context.Background()

var NoOptions = options.SetOptions{}

func Run(command string, args ...string) {
	_ = run(true, command, args...)
}

func RunMayFail(command string, args ...string) error {
	return run(false, command, args...)
}

var currentTestOutput = []string{}

var LastRunOutput string

func run(checkNoError bool, command string, args ...string) error {
	outputBytes, err := Command(command, args...).CombinedOutput()
	currentTestOutput = append(currentTestOutput, fmt.Sprintf("Command: %v %v\n", command, args))
	currentTestOutput = append(currentTestOutput, string(outputBytes))
	LastRunOutput = string(outputBytes)
	if err != nil {
		log.WithFields(log.Fields{
			"command": command,
			"args":    args,
			"output":  string(outputBytes)}).WithError(err).Warning("Command failed")
	}
	if checkNoError {
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Command failed\nCommand: %v args: %v\nOutput:\n\n%v",
			command, args, string(outputBytes)))
	}
	return err
}

func AddToTestOutput(args ...string) {
	currentTestOutput = append(currentTestOutput, args...)
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

func GetCommandOutput(command string, args ...string) (string, error) {
	cmd := Command(command, args...)
	log.Infof("Running '%s %s'", cmd.Path, strings.Join(cmd.Args, " "))
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func RunCommand(command string, args ...string) error {
	output, err := GetCommandOutput(command, args...)
	log.Infof("output: %v", output)
	return err
}

func Command(name string, args ...string) *exec.Cmd {
	log.WithFields(log.Fields{
		"command":     name,
		"commandArgs": args,
	}).Info("Creating Command.")

	return exec.Command(name, args...)
}

func LogOutput(cmd *exec.Cmd, name string) error {
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Getting StdoutPipe failed for %s: %v", name, err)
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("Getting StderrPipe failed for %s: %v", name, err)
	}
	stdoutReader := bufio.NewReader(outPipe)
	stderrReader := bufio.NewReader(errPipe)
	go func() {
		for {
			line, err := stdoutReader.ReadString('\n')
			if err != nil {
				log.WithError(err).Infof("End of %s stdout", name)
				return
			}
			log.Infof("%s stdout: %s", name, strings.TrimSpace(string(line)))
		}
	}()
	go func() {
		for {
			line, err := stderrReader.ReadString('\n')
			if err != nil {
				log.WithError(err).Infof("End of %s stderr", name)
				return
			}
			log.Infof("%s stderr: %s", name, strings.TrimSpace(string(line)))
		}
	}()
	return nil
}

func GetEtcdClient(etcdIP string) client.Interface {
	client, err := client.New(apiconfig.CalicoAPIConfig{
		Spec: apiconfig.CalicoAPIConfigSpec{
			DatastoreType: apiconfig.EtcdV3,
			EtcdConfig: apiconfig.EtcdConfig{
				EtcdEndpoints: "http://" + etcdIP + ":2379",
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	return client
}

func IPSetIDForSelector(rawSelector string) string {
	sel, err := selector.Parse(rawSelector)
	Expect(err).ToNot(HaveOccurred())

	ipSetData := calc.IPSetData{
		Selector: sel,
	}
	setID := ipSetData.UniqueID()
	return setID
}

func IPSetNameForSelector(ipVersion int, rawSelector string) string {
	setID := IPSetIDForSelector(rawSelector)
	var ipFamily ipsets.IPFamily
	if ipVersion == 4 {
		ipFamily = ipsets.IPFamilyV4
	} else {
		ipFamily = ipsets.IPFamilyV6
	}
	ipVerConf := ipsets.NewIPVersionConfig(
		ipFamily,
		rules.IPSetNamePrefix,
		nil,
		nil,
	)

	return ipVerConf.NameForMainIPSet(setID)
}

// Run a connection test command.
// Report if connection test is successful and packet loss string for packet loss test.
func RunConnectionCmd(connectionCmd *exec.Cmd, logMsg string) *connectivity.Result {
	outPipe, err := connectionCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	errPipe, err := connectionCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())
	err = connectionCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	var wg sync.WaitGroup
	wg.Add(2)
	var wOut, wErr []byte
	var outErr, errErr error

	go func() {
		defer wg.Done()
		wOut, outErr = ioutil.ReadAll(outPipe)
	}()

	go func() {
		defer wg.Done()
		wErr, errErr = ioutil.ReadAll(errPipe)
	}()

	wg.Wait()
	Expect(outErr).NotTo(HaveOccurred())
	Expect(errErr).NotTo(HaveOccurred())

	err = connectionCmd.Wait()

	log.WithFields(log.Fields{
		"stdout": string(wOut),
		"stderr": string(wErr)}).WithError(err).Info(logMsg)

	if err != nil {
		return nil
	}

	r := regexp.MustCompile(`RESULT=(.*)\n`)
	m := r.FindSubmatch(wOut)
	if len(m) > 0 {
		var resp connectivity.Result
		err := json.Unmarshal(m[1], &resp)
		if err != nil {
			log.WithError(err).WithField("output", string(wOut)).Panic("Failed to parse connection check response")
		}
		return &resp
	}
	return nil
}

const ConnectionTypeStream = "stream"
const ConnectionTypePing = "ping"

type ConnConfig struct {
	ConnType string
	ConnID   string
}

func (cc ConnConfig) getTestMessagePrefix() string {
	return cc.ConnType + ":" + cc.ConnID + "~"
}

// Assembly a test message.
func (cc ConnConfig) GetTestMessage(sequence int) connectivity.Request {
	req := connectivity.NewRequest(cc.getTestMessagePrefix() + fmt.Sprintf("%d", sequence))
	return req
}

// Extract sequence number from test message.
func (cc ConnConfig) GetTestMessageSequence(msg string) (int, error) {
	msg = strings.TrimSpace(msg)
	seqString := strings.TrimPrefix(msg, cc.getTestMessagePrefix())
	if seqString == msg {
		// TrimPrefix failed.
		return 0, errors.New("invalid message prefix format:" + msg)
	}

	seq, err := strconv.Atoi(seqString)
	if err != nil || seq < 0 {
		return 0, errors.New("invalid message sequence format:" + msg)
	}
	return seq, nil
}

func IsMessagePartOfStream(msg string) bool {
	return strings.HasPrefix(strings.TrimSpace(msg), ConnectionTypeStream)
}
