package calico

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCalico(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Calico Suite")
}
