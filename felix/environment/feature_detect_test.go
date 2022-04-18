// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.
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

package environment_test

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/iptables/testutils"
)

func TestFeatureDetection(t *testing.T) {
	RegisterTestingT(t)

	type test struct {
		iptablesVersion, kernelVersion string
		features                       Features
	}
	for _, tst := range []test{
		{
			"iptables v1.6.2",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       true,
				MASQFullyRandom:       true,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.6.1",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   false,
				SNATFullyRandom:       true,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.5.0",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   false,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.6.2",
			"Linux version 3.13.0",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"garbage",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   false,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.6.2",
			"garbage",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"error",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   false,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.6.2",
			"error",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       false,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
		},
		{
			"iptables v1.8.4",
			"Linux version 5.7.0",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       true,
				MASQFullyRandom:       true,
				ChecksumOffloadBroken: false,
			},
		},
	} {
		tst := tst
		t.Run("iptables version "+tst.iptablesVersion+" kernel "+tst.kernelVersion, func(t *testing.T) {
			RegisterTestingT(t)
			dataplane := testutils.NewMockDataplane("filter", map[string][]string{}, "legacy")
			featureDetector := NewFeatureDetector(nil)
			featureDetector.NewCmd = dataplane.NewCmd
			featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader

			if tst.iptablesVersion == "error" {
				dataplane.FailNextVersion = true
			} else {
				dataplane.Version = tst.iptablesVersion
			}

			if tst.kernelVersion == "error" {
				dataplane.FailNextGetKernelVersionReader = true
			} else {
				dataplane.KernelVersion = tst.kernelVersion
			}

			Expect(featureDetector.GetFeatures()).To(Equal(&tst.features))
		})
	}
}

func TestFeatureDetectionOverride(t *testing.T) {
	RegisterTestingT(t)

	type test struct {
		iptablesVersion, kernelVersion string
		features                       Features
		override                       map[string]string
	}
	for _, tst := range []test{
		{
			"iptables v1.6.2",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       true,
				MASQFullyRandom:       true,
				ChecksumOffloadBroken: true,
			},
			map[string]string{},
		},
		{
			"iptables v1.6.1",
			"Linux version 3.14.0",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       true,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
			map[string]string{
				"RestoreSupportsLock": "true",
			},
		},
		{
			"error",
			"error",
			Features{
				RestoreSupportsLock:   true,
				SNATFullyRandom:       true,
				MASQFullyRandom:       false,
				ChecksumOffloadBroken: true,
			},
			map[string]string{
				"RestoreSupportsLock": "true",
				"SNATFullyRandom":     "true",
				"MASQFullyRandom":     "false",
			},
		},
	} {
		tst := tst
		t.Run("iptables version "+tst.iptablesVersion+" kernel "+tst.kernelVersion, func(t *testing.T) {
			RegisterTestingT(t)
			dataplane := testutils.NewMockDataplane("filter", map[string][]string{}, "legacy")
			featureDetector := NewFeatureDetector(tst.override)
			featureDetector.NewCmd = dataplane.NewCmd
			featureDetector.GetKernelVersionReader = dataplane.GetKernelVersionReader

			if tst.iptablesVersion == "error" {
				dataplane.FailNextVersion = true
			} else {
				dataplane.Version = tst.iptablesVersion
			}

			if tst.kernelVersion == "error" {
				dataplane.FailNextGetKernelVersionReader = true
			} else {
				dataplane.KernelVersion = tst.kernelVersion
			}

			Expect(featureDetector.GetFeatures()).To(Equal(&tst.features))
		})
	}
}

func TestIptablesBackendDetection(t *testing.T) {
	RegisterTestingT(t)

	type test struct {
		name            string
		spec            string
		cmdF            ipOutputFactory
		expectedBackend string
	}
	for _, tst := range []test{
		{
			"No output from cmds",
			"auto",
			ipOutputFactory{0, 0, 0, 0},
			"legacy",
		},
		{
			"Output from legacy cmds",
			"auto",
			ipOutputFactory{10, 10, 0, 0},
			"legacy",
		},
		{
			"Output from nft cmds",
			"auto",
			ipOutputFactory{0, 0, 10, 10},
			"nft",
		},
		{
			"Detected and Specified backend of nft match",
			"nft",
			ipOutputFactory{0, 0, 10, 10},
			"nft",
		},
		{
			"Detected and Specified backend of legacy match",
			"legacy",
			ipOutputFactory{10, 10, 0, 0},
			"legacy",
		},
		{
			"Backend detected as nft does not match Specified legacy",
			"legacy",
			ipOutputFactory{0, 0, 10, 10},
			"legacy",
		},
		{
			"Backend detected as legacy does not match Specified nft",
			"nft",
			ipOutputFactory{10, 10, 0, 0},
			"nft",
		},
		{
			"Errors from commands still causes legacy detection",
			"auto",
			ipOutputFactory{
				Ip6legacy: -1,
				Ip4legacy: -1,
				Ip6Nft:    -1,
				Ip4Nft:    -1,
			},
			"legacy",
		},
		{
			"Only ipv4 output from legacy cmds",
			"auto",
			ipOutputFactory{
				Ip6legacy: -1,
				Ip4legacy: 15,
				Ip6Nft:    10,
				Ip4Nft:    10,
			},
			"legacy",
		},
		{
			"Only ipv6 output from legacy cmds",
			"auto",
			ipOutputFactory{
				Ip6legacy: 15,
				Ip4legacy: -1,
				Ip6Nft:    10,
				Ip4Nft:    10,
			},
			"legacy",
		},
		{
			"Only ipv6 output from nft cmds still detects nft",
			"auto",
			ipOutputFactory{
				Ip6legacy: 4,
				Ip4legacy: 4,
				Ip6Nft:    15,
				Ip4Nft:    -1,
			},
			"nft",
		},
	} {
		tst := tst
		t.Run("DetectingBackend, testing "+tst.name, func(t *testing.T) {
			RegisterTestingT(t)
			Expect(DetectBackend(testutils.LookPathAll, tst.cmdF.NewCmd, tst.spec)).To(Equal(tst.expectedBackend))

			Expect(DetectBackend(testutils.LookPathAll, tst.cmdF.NewCmd, strings.ToUpper(tst.spec))).To(Equal(tst.expectedBackend), "Capitalization affected output")
		})
	}
}

type ipOutputFactory struct {
	Ip6legacy int
	Ip4legacy int
	Ip6Nft    int
	Ip4Nft    int
}

func (f *ipOutputFactory) NewCmd(name string, arg ...string) cmdshim.CmdIface {
	switch name {
	case "iptables-legacy-save":
		return &ipOutputCmd{out: f.Ip4legacy}
	case "ip6tables-legacy-save":
		return &ipOutputCmd{out: f.Ip6legacy}
	case "iptables-nft-save":
		return &ipOutputCmd{out: f.Ip4Nft}
	case "ip6tables-nft-save":
		return &ipOutputCmd{out: f.Ip6Nft}
	}
	return nil
}

type ipOutputCmd struct {
	out int
}

func (d *ipOutputCmd) String() string {
	return ""
}

func (d *ipOutputCmd) SetStdin(r io.Reader) {
	Fail("Not implemented")
}

func (d *ipOutputCmd) SetStdout(w io.Writer) {
	Fail("Not implemented")
}

func (d *ipOutputCmd) SetStderr(w io.Writer) {
	Fail("Not implemented")
}

func (d *ipOutputCmd) Start() error {
	return errors.New("Not implemented")
}

func (d *ipOutputCmd) Wait() error {
	return errors.New("Not implemented")
}

func (d *ipOutputCmd) Kill() error {
	return errors.New("Not implemented")
}

func (d *ipOutputCmd) Output() ([]byte, error) {
	if d.out < 0 {
		return nil, errors.New("iptables command failed")
	}
	out := []byte{}
	for i := 0; i < d.out; i++ {
		out = append(out, []byte(fmt.Sprintf("-Output line %d\n", i))...)
	}
	return out, nil
}

func (d *ipOutputCmd) StdoutPipe() (io.ReadCloser, error) {
	return nil, errors.New("Not implemented")
}

func (d *ipOutputCmd) Run() error {
	return errors.New("Not implemented")
}
