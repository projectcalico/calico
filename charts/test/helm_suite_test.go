package charttest

import (
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestHelm(t *testing.T) {
	// testutils.HookLogrusForGinkgo()
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/helm_suite.xml")

	_, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("skipping exec tests since 'helm' is not installed")
	}

	RunSpecsWithDefaultAndCustomReporters(t, "Helm Suite", []Reporter{junitReporter})
}
