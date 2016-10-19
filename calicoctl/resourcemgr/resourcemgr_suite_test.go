package resourcemgr_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestResourcemgr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resourcemgr Suite")
}
