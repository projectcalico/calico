// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package counter

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
	logutils.ConfigureFormatter("test")
}

func TestCounter(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/counter_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Counter Suite", []Reporter{junitReporter})
}
