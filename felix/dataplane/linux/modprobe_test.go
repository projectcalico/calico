// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("modprobe", func() {
	var (
		cmdRecorder mpTestCmdRecorder
		uut         modProbe
	)

	BeforeEach(func() {
		cmd := &mpTestCmd{output: []byte("test output"), err: errors.New("test mp error")}
		cmdRecorder = mpTestCmdRecorder{cmds: []*mpTestCmd{cmd}}
		uut = newModProbe("test_module", cmdRecorder.factory)
	})

	It("should return command output and error", func() {
		out, err := uut.Exec()
		Expect(out).To(Equal("test output"))
		Expect(err).To(Equal(errors.New("test mp error")))
		Expect(cmdRecorder.cmds[0].outputCallCount).To(Equal(1))
	})
})

type mpTestCmdRecorder struct {
	cmds []*mpTestCmd
	next int
}

type mpTestCmd struct {
	output          []byte
	err             error
	outputCallCount int
}

func (m *mpTestCmd) Output() ([]byte, error) {
	m.outputCallCount++
	return m.output, m.err
}

func (r *mpTestCmdRecorder) factory(name string, args ...string) cmdIface {
	cmd := r.cmds[r.next]
	r.next++
	return cmd
}
