// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package yaml_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func TestYaml(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/yaml_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Yaml Suite", []Reporter{junitReporter})
}
