// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package commands_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestCommands(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/commands_suite.xml"
	ginkgo.RunSpecs(t, "Commands Suite", suiteConfig, reporterConfig)
}
