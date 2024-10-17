package calico

import (
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func TestCalico(t *testing.T) {
	testutils.HookLogrusForGinkgo()
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../../report/calico_backend_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Calico Backend Suite", []Reporter{junitReporter})
}
