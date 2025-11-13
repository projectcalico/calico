package felix_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestFelix(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("./report/felix_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix", []Reporter{junitReporter})
}
