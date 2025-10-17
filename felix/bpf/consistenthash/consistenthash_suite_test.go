package consistenthash

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestConsistentHash(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BPF ConsistentHash Suite")
}
