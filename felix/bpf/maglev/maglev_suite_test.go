package maglev

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestMaglev(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BPF Maglev Suite")
}
