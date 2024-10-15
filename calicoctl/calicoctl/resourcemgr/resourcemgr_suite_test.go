// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package resourcemgr_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
)

func TestResourcemgr(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/resourcemgr_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Resourcemgr Suite", []Reporter{junitReporter})
}
