// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

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

package cluster

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

func init() {
	logutils.ConfigureFormatter("test")
}

func TestDiags(t *testing.T) {
	RegisterTestingT(t)
	test := func(invocation string, expectedErr error, expectedOutput string, expectedOpts *diagOpts) {
		logrus.Infof("Test case: %v", invocation)
		output := ""
		opts := (*diagOpts)(nil)
		err := diagsTestable(
			strings.Split(invocation, " "),
			func(a ...any) (int, error) {
				output = fmt.Sprint(a...)
				return 0, nil
			}, func(o *diagOpts) error {
				opts = o
				return nil
			})
		if expectedErr == nil {
			Expect(err).To(BeNil())
		} else {
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedErr.Error()))
		}
		Expect(output).To(Equal(expectedOutput))
		if expectedOpts != nil {
			// Save having to specify Cluster and Diags in all of the cases below.
			expectedOpts.Cluster = true
			expectedOpts.Diags = true
		}
		Expect(opts).To(Equal(expectedOpts))
	}
	test("cluster diags",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags -h",
		nil,
		doc,
		nil)
	test("cluster diags --help",
		nil,
		doc,
		nil)
	test("cluster diags rubbish",
		errors.New("Invalid option: 'calicoctl cluster diags rubbish'.\n\n"+usage),
		"",
		nil)
	test("cluster diags --rubbish",
		errors.New("Invalid option: 'calicoctl cluster diags --rubbish'.\n\n"+usage),
		"",
		nil)
	test("cluster diags -c /configfile",
		nil,
		"",
		&diagOpts{
			Config:               "/configfile",
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --config /configfile",
		nil,
		"",
		&diagOpts{
			Config:               "/configfile",
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --since 3h",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "3h",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --max-logs 1 --max-parallelism 2",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "0s",
			MaxLogs:              1,
			MaxParallelism:       2,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --max-logs=1",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "0s",
			MaxLogs:              1,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --focus-node=infra1,control2",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "infra1,control2",
			AllowVersionMismatch: false,
		})
}
