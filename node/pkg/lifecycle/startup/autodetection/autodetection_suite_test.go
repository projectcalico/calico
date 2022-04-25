package autodetection_test

import (
	. "github.com/onsi/ginkgo/v2"
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
	junitReporter := reporters.NewJUnitReporter("../../../report/autodetection_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Autodetection Suite", []Reporter{junitReporter})
}
