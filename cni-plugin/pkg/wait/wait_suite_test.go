//  Copyright (c) 2024 Tigera, Inc. All rights reserved.

package wait

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"

	"github.com/onsi/ginkgo/reporters"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestInstall(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/status_wait_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Status Wait Suite", []Reporter{junitReporter})
}
