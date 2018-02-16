// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/calc"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/rules"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/selector"
)

type EnvConfig struct {
	FelixImage string `default:"calico/felix:latest"`
	EtcdImage  string `default:"quay.io/coreos/etcd"`
	K8sImage   string `default:"gcr.io/google_containers/hyperkube-amd64:v1.7.5"`
	TyphaImage string `default:"calico/typha:latest"` // Note: this is overridden in the Makefile!
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

func GetEtcdClient(etcdIP string, alphaFeatures string) client.Interface {
	client, err := client.New(apiconfig.CalicoAPIConfig{
		Spec: apiconfig.CalicoAPIConfigSpec{
			DatastoreType: apiconfig.EtcdV3,
			EtcdConfig: apiconfig.EtcdConfig{
				EtcdEndpoints: "http://" + etcdIP + ":2379",
			},
			AlphaFeatures: alphaFeatures,
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
