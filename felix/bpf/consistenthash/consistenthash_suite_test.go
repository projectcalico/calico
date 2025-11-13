package consistenthash

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

func TestConsistentHash(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("../../report/felix_bpf_consistenthash_suite.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "UT: felix/bpf/consistenthash", []Reporter{junitReporter})
}
