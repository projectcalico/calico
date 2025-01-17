// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package events

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestEvents(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../report/events_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Events Suite", []Reporter{junitReporter})
}
