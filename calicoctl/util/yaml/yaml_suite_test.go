package yaml_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestYaml(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Yaml Suite")
}
