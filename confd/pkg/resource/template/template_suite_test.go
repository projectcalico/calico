package template

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestTemplate(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/template_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Template Suite", []Reporter{junitReporter})
}
