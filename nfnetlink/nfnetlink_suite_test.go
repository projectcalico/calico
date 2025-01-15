// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
package nfnetlink_test

import (
	"testing"

	"github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestNfnetlink(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	junitReporter := reporters.NewJUnitReporter("../report/ip_suite.xml")
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "Nfnetlink Suite", []ginkgo.Reporter{junitReporter})
}

func init() {
	testutils.HookLogrusForGinkgo()
	logutils.ConfigureFormatter("test")
}
