package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestCalicoCni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CalicoCni Suite")
}
