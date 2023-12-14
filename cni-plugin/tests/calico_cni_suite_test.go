//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCalicoCni(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../report/cni_suite.xml"
	ginkgo.RunSpecs(t, "CNI suite", suiteConfig, reporterConfig)
}
