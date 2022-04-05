// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/rules"
)

type EnvConfig struct {
	// Note: These are overridden in the Makefile!
	FelixImage   string `default:"calico/felix:latest"`
	EtcdImage    string `default:"quay.io/coreos/etcd"`
	K8sImage     string `default:"calico/go-build:latest"`
	TyphaImage   string `default:"calico/typha:latest"`
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
	_ = run(nil, true, command, args...)
}

func RunWithInput(input []byte, command string, args ...string) {
	_ = run(input, true, command, args...)
}

func RunMayFail(command string, args ...string) error {
	return run(nil, false, command, args...)
}

var LastRunOutput string

func run(input []byte, checkNoError bool, command string, args ...string) error {
	cmd := Command(command, args...)
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)
	LastRunOutput = string(outputBytes)
	formattedCmd := formatCommand(command, args)
	if err != nil {
		if len(output) == 0 {
			log.WithError(err).Warningf("Command failed [%s]: <no output>", formattedCmd)
		} else {
			log.WithError(err).Warningf("Command failed [%s]:\n%s", formattedCmd, indent(output, "\t"))
		}
	} else {
		if len(output) == 0 {
			log.Infof("Command succeeded [%s]: <no output>", formattedCmd)
		} else {
			log.Infof("Command succeeded [%s]:\n%s", formattedCmd, indent(output, "\t"))
		}
	}
	if checkNoError {
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Command failed\nCommand: %v args: %v\nOutput:\n\n%v",
			command, args, string(outputBytes)))
	}
	if err != nil {
		return fmt.Errorf("Command failed\nCommand: %v args: %v\nOutput:\n\n%v\n\nOrig error: %w",
			command, args, string(outputBytes), err)
	}
	return nil
}

func indent(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

func formatCommand(command string, args []string) string {
	out := command
	for _, arg := range args {
		// Only quote if there are actually some interesting characters in there, just to make it easier to read.
		quoted := fmt.Sprintf("%q", arg)
		if quoted == `"`+arg+`"` {
			out += " " + arg
		} else {
			out += " " + quoted
		}
	}
	return out
}

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
	log.Debugf("Creating Command [%s].", formatCommand(name, args))

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

// HasSyscallConn represents objects that can return a syscall.RawConn
type HasSyscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// ConnMTU returns the MTU of the connection for _connected_ connections. That
// excludes unconnected udp which requires different approach for each peer.
func ConnMTU(hsc HasSyscallConn) (int, error) {
	c, err := hsc.SyscallConn()
	if err != nil {
		return 0, err
	}

	mtu := 0
	var sysErr error
	err = c.Control(func(fd uintptr) {
		mtu, sysErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU)
	})

	if err != nil {
		return 0, err
	}

	if sysErr != nil {
		return 0, sysErr
	}

	return mtu, nil
}

func UpdateFelixConfig(client client.Interface, deltaFn func(*api.FelixConfiguration)) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	if _, doesNotExist := err.(cerrors.ErrorResourceDoesNotExist); doesNotExist {
		cfg = api.NewFelixConfiguration()
		cfg.Name = "default"
		deltaFn(cfg)
		_, err = client.FelixConfigurations().Create(ctx, cfg, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	} else {
		Expect(err).NotTo(HaveOccurred())
		deltaFn(cfg)
		_, err = client.FelixConfigurations().Update(ctx, cfg, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}
