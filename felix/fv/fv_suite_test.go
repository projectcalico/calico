// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	"github.com/onsi/gomega/format"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var realStdout = os.Stdout

func init() {
	testutils.HookLogrusForGinkgo()

	// Avoid truncating diffs when Equals assertions fail.
	format.TruncatedDiff = false
}

func TestFv(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../report/fv_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "FV Suite", []Reporter{junitReporter})
}

var _ = BeforeEach(func() {
	_, _ = fmt.Fprintf(realStdout, "\nFV-TEST-START: %s", CurrentGinkgoTestDescription().FullTestText)
})

var _ = JustAfterEach(func() {
	if CurrentGinkgoTestDescription().Failed {
		_, _ = fmt.Fprintf(realStdout, "\n")
	}
})

var _ = AfterEach(func() {
	defer connectivity.UnactivatedCheckers.Clear()
	if CurrentGinkgoTestDescription().Failed {
		// If the test has already failed, ignore any connectivity checker leak.
		return
	}
	Expect(connectivity.UnactivatedCheckers.Len()).To(BeZero(),
		"Test bug: ConnectivityChecker was created but not activated.")
})

var _ = AfterSuite(func() {
	if infrastructure.K8sInfra != nil {
		infrastructure.TearDownK8sInfra(infrastructure.K8sInfra)
		infrastructure.K8sInfra = nil
	}
	infrastructure.RemoveTLSCredentials()
})
