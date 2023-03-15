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
	"bytes"
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
				RestoreSupportsLock:      true,
				SNATFullyRandom:          true,
				MASQFullyRandom:          true,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
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
			ipOutputFactory{0, 0, 0, 0, 0, 0, 0, 0},
			"legacy",
		},
		{
			"Output from legacy cmds",
			"auto",
			ipOutputFactory{10, 10, 0, 0, 0, 0, 0, 0},
			"legacy",
		},
		{
			"Output from nft cmds",
			"auto",
			ipOutputFactory{0, 0, 10, 10, 0, 0, 0, 0},
			"nft",
		},
		{
			"Detected and Specified backend of nft match",
			"nft",
			ipOutputFactory{0, 0, 10, 10, 0, 0, 0, 0},
			"nft",
		},
		{
			"Detected and Specified backend of legacy match",
			"legacy",
			ipOutputFactory{10, 10, 0, 0, 0, 0, 0, 0},
			"legacy",
		},
		{
			"Backend detected as nft does not match Specified legacy",
			"legacy",
			ipOutputFactory{0, 0, 10, 10, 0, 0, 0, 0},
			"legacy",
		},
		{
			"Backend detected as legacy does not match Specified nft",
			"nft",
			ipOutputFactory{10, 10, 0, 0, 0, 0, 0, 0},
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
			"nft",
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
			"nft",
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
		{
			"Output from nft with kube chains",
			"auto",
			ipOutputFactory{
				Ip6legacy:     0,
				Ip4legacy:     0,
				Ip6Nft:        64,
				Ip4Nft:        123,
				Ip6legacyKube: 0,
				Ip4legacyKube: 0,
				Ip6NftKube:    2,
				Ip4NftKube:    2,
			},
			"nft",
		},
		{
			"Output from nft with kube chains and has legacy chains",
			"auto",
			ipOutputFactory{
				Ip6legacy:     20,
				Ip4legacy:     20,
				Ip6Nft:        2,
				Ip4Nft:        2,
				Ip6legacyKube: 0,
				Ip4legacyKube: 0,
				Ip6NftKube:    2,
				Ip4NftKube:    2,
			},
			"nft",
		}, {
			"Output from legacy with kube chains and has nft chains",
			"auto",
			ipOutputFactory{
				Ip6legacy:     20,
				Ip4legacy:     20,
				Ip6Nft:        30,
				Ip4Nft:        30,
				Ip6legacyKube: 2,
				Ip4legacyKube: 2,
				Ip6NftKube:    0,
				Ip4NftKube:    0,
			},
			"legacy",
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

	Ip6legacyKube int
	Ip4legacyKube int
	Ip6NftKube    int
	Ip4NftKube    int
}

func (f *ipOutputFactory) NewCmd(name string, arg ...string) cmdshim.CmdIface {
	switch name {
	case "iptables-legacy-save":
		return &ipOutputCmd{out: f.Ip4legacy, outKube: f.Ip4legacyKube}
	case "ip6tables-legacy-save":
		return &ipOutputCmd{out: f.Ip6legacy, outKube: f.Ip6legacyKube}
	case "iptables-nft-save":
		return &ipOutputCmd{out: f.Ip4Nft, outKube: f.Ip4NftKube}
	case "ip6tables-nft-save":
		return &ipOutputCmd{out: f.Ip6Nft, outKube: f.Ip6NftKube}
	}
	return nil
}

type ipOutputCmd struct {
	out     int
	outKube int
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
	if d.outKube > d.out {
		return nil, errors.New("iptables command failed")
	}

	out := []byte{}
	for i := 0; i < d.outKube; i++ {
		out = append(out, []byte(fmt.Sprintf("KUBE-IPTABLES-HINT - [0:0] %d\n", i))...)
	}
	for i := 0; i < d.out-d.outKube; i++ {
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

func TestBPFFeatureDetection(t *testing.T) {
	RegisterTestingT(t)

	type test struct {
		kernelVersion string
		features      Features
		override      map[string]string
	}
	for _, tst := range []test{
		{
			"Linux version 5.10.0 - ubuntu",
			Features{
				IPIPDeviceIsL3:           false,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 5.14.0 - something else",
			Features{
				IPIPDeviceIsL3:           true,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 5.15.0",
			Features{
				IPIPDeviceIsL3:           true,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 5.10.0 - Default",
			Features{
				IPIPDeviceIsL3:           true,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "true",
			},
		},
		{
			"Linux version 5.14.0",
			Features{
				IPIPDeviceIsL3:           false,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 5.16.0 - Ubuntu",
			Features{
				IPIPDeviceIsL3:           false,
				ChecksumOffloadBroken:    true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 4.18.0 - Red Hat",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           false,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 4.18.0-330 - Red Hat",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 4.18.0-420 - Red hat",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{},
		},
		{
			"Linux version 4.17.0 - el8_3",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           true,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "true",
			},
		},
		{
			"Linux version 4.18.0-330 - el8_5",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           false,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 4.18.0-390 - el9_7",
			Features{
				ChecksumOffloadBroken:    true,
				IPIPDeviceIsL3:           false,
				KernelSideRouteFiltering: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
	} {
		t.Run("kernel "+tst.kernelVersion, func(t *testing.T) {
			RegisterTestingT(t)
			dataplane := testutils.NewMockDataplane("filter", map[string][]string{}, "legacy")
			dataplane.Version = "iptables v1.4.4"
			featureDetector := NewFeatureDetector(nil)
			if tst.override != nil {
				featureDetector = NewFeatureDetector(tst.override)
			}
			kernel := mockKernelVersion{
				kernelVersion: tst.kernelVersion,
			}
			featureDetector.NewCmd = dataplane.NewCmd
			featureDetector.GetKernelVersionReader = kernel.GetKernelVersionReader
			Expect(featureDetector.GetFeatures()).To(Equal(&tst.features))
		})
	}
}

type mockKernelVersion struct {
	kernelVersion string
}

func (kv mockKernelVersion) GetKernelVersionReader() (io.Reader, error) {
	return bytes.NewBufferString(kv.kernelVersion), nil
}
