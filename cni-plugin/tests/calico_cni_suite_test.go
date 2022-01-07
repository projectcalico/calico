//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_test

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

func TestCalicoCni(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../report/cni_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "CNI suite", []Reporter{junitReporter})
}
