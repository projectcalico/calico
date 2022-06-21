package libbpf

import (
	"runtime"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNumPossibleCPUs(t *testing.T) {
	RegisterTestingT(t)
	actual, err := NumPossibleCPUs()

	Expect(err).NotTo(HaveOccurred())
	Expect(actual).Should(BeNumerically(">=", runtime.NumCPU()))
}
