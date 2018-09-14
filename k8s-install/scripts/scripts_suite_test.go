//  Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

package scripts_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func TestScripts(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/scripts_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Scripts Suite", []Reporter{junitReporter})
}
