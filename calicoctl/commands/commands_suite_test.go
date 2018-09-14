// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package commands_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func TestCommands(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/commands_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Commands Suite", []Reporter{junitReporter})
}
