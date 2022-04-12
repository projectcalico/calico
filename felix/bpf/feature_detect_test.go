// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package bpf_test

import (
	"bytes"
	"io"
	"testing"

	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/bpf"
)

func TestFeatureDetection(t *testing.T) {
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
				IPIPDeviceIsL3: false,
			},
			map[string]string{},
		},
		{
			"Linux version 5.14.0 - something else",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{},
		},
		{
			"Linux version 5.15.0",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{},
		},
		{
			"Linux version 5.10.0 - Default",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "true",
			},
		},
		{
			"Linux version 5.14.0",
			Features{
				IPIPDeviceIsL3: false,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 5.16.0 - Ubuntu",
			Features{
				IPIPDeviceIsL3: false,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 4.18.0 - Red Hat",
			Features{
				IPIPDeviceIsL3: false,
			},
			map[string]string{},
		},
		{
			"Linux version 4.18.0-330 - Red Hat",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{},
		},
		{
			"Linux version 4.18.0-420 - Red hat",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{},
		},
		{
			"Linux version 4.17.0 - el8_3",
			Features{
				IPIPDeviceIsL3: true,
			},
			map[string]string{
				"IPIPDeviceIsL3": "true",
			},
		},
		{
			"Linux version 4.18.0-330 - el8_5",
			Features{
				IPIPDeviceIsL3: false,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
		{
			"Linux version 4.18.0-390 - el9_7",
			Features{
				IPIPDeviceIsL3: false,
			},
			map[string]string{
				"IPIPDeviceIsL3": "false",
			},
		},
	} {
		t.Run("kernel "+tst.kernelVersion, func(t *testing.T) {
			RegisterTestingT(t)
			featureDetector := NewFeatureDetector(nil)
			if tst.override != nil {
				featureDetector = NewFeatureDetector(tst.override)
			}
			kernel := mockKernelVersion{
				kernelVersion: tst.kernelVersion,
			}
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
