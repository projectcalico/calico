//  Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

package install_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestInstall(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/install_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Install Suite", []Reporter{junitReporter})
}
