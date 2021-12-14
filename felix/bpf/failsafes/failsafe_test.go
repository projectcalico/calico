// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

// Copyright (c) 2021  All rights reserved.

package failsafes

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/logutils"
)

const zeroValue = "\x00\x00\x00\x00"

type failsafeTest struct {
	Name                string
	InitialMapContents  map[string]string
	In, Out             []config.ProtoPort
	ExpectedMapContents map[string]string
}

func (f *failsafeTest) Run(t *testing.T) {
	RegisterTestingT(t)
	mockMap := mock.NewMockMap(MapParams)
	if f.InitialMapContents != nil {
		mockMap.Contents = f.InitialMapContents
	}

	opReporter := logutils.NewSummarizer("test")
	mgr := NewManager(mockMap, f.In, f.Out, opReporter)

	err := mgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.Contents).To(Equal(f.ExpectedMapContents))

	opCount := mockMap.OpCount()
	err = mgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	Expect(mockMap.OpCount()).To(Equal(opCount), "failsafes manager should only execute if not in sync")
}

var tests = []failsafeTest{
	{
		Name:                "EmptyShouldGiveEmptyMap",
		ExpectedMapContents: map[string]string{},
	},
	{
		Name: "ShouldFillEmptyMap",
		In: []config.ProtoPort{
			{Protocol: "tcp", Port: 22, Net: "0.0.0.0/0"},
			{Protocol: "udp", Port: 1234, Net: "0.0.0.0/0"},
		},
		Out: []config.ProtoPort{
			{Protocol: "tcp", Port: 443, Net: "0.0.0.0/0"},
			{Protocol: "udp", Port: 53, Net: "0.0.0.0/0"},
		},
		ExpectedMapContents: map[string]string{
			string(Key{Port: 22, IPProto: 6, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                       zeroValue,
			string(Key{Port: 1234, IPProto: 17, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                    zeroValue,
			string(Key{Port: 443, IPProto: 6, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
			string(Key{Port: 53, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
		},
	},
	{
		Name: "ShouldResyncDirtyMap",
		In: []config.ProtoPort{
			{Protocol: "tcp", Port: 22, Net: "0.0.0.0/0"},
			{Protocol: "udp", Port: 1234, Net: "0.0.0.0/0"},
		},
		Out: []config.ProtoPort{
			{Protocol: "tcp", Port: 443, Net: "0.0.0.0/0"},
			{Protocol: "udp", Port: 53, Net: "0.0.0.0/0"},
		},
		InitialMapContents: map[string]string{
			string(Key{Port: 22, IPProto: 6, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                        zeroValue,
			string(Key{Port: 2345, IPProto: 17, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                     zeroValue,
			string(Key{Port: 1443, IPProto: 6, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
			string(Key{Port: 53, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()):  zeroValue,
			string(Key{Port: 57, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()):  zeroValue,
		},
		ExpectedMapContents: map[string]string{
			string(Key{Port: 22, IPProto: 6, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                       zeroValue,
			string(Key{Port: 1234, IPProto: 17, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                    zeroValue,
			string(Key{Port: 443, IPProto: 6, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
			string(Key{Port: 53, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
		},
	},
	{
		Name: "ShouldRemoveAll",
		InitialMapContents: map[string]string{
			string(Key{Port: 22, IPProto: 6, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                        zeroValue,
			string(Key{Port: 2345, IPProto: 17, IP: "0.0.0.0", IPMask: 0}.ToSlice()):                     zeroValue,
			string(Key{Port: 1443, IPProto: 6, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()): zeroValue,
			string(Key{Port: 53, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()):  zeroValue,
			string(Key{Port: 57, IPProto: 17, Flags: FlagOutbound, IP: "0.0.0.0", IPMask: 0}.ToSlice()):  zeroValue,
		},
		ExpectedMapContents: map[string]string{},
	},
}

func TestManager(t *testing.T) {
	for _, test := range tests {
		t.Run(test.Name, test.Run)
	}
}
