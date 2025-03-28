package felix_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestFelix(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Felix Suite")
}
