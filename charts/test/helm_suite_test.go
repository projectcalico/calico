package charttest

import (
	"os/exec"
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestHelm(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "../../report/helm_suite.xml"

	_, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("skipping exec tests since 'helm' is not installed")
	}

	ginkgo.RunSpecs(t, "Helm Suite", suiteConfig, reporterConfig)
}
