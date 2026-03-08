// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package yaml_test

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestYaml(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../../report/yaml_suite.xml"
	ginkgo.RunSpecs(t, "Yaml Suite", suiteConfig, reporterConfig)
}
