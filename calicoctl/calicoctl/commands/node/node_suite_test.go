// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package node_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCommands(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/node_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Node Suite", []Reporter{junitReporter})
}
