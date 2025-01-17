// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package tuple

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

func TestTuple(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/tuple_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Tuple Suite", []Reporter{junitReporter})
}
