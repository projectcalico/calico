// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package yaml_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestYaml(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/yaml_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Yaml Suite", []Reporter{junitReporter})
}
