package windataplane_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestWindataplane(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Windataplane Suite")
}
