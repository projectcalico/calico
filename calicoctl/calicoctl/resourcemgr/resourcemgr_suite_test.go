// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package resourcemgr_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestResourcemgr(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/resourcemgr_suite.xml"
	ginkgo.RunSpecs(t, "Resourcemgr Suite", suiteConfig, reporterConfig)
}
