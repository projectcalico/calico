//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func TestCalicoCni(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("./report/cni_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "CalicoCni Suite", []Reporter{junitReporter})
}
