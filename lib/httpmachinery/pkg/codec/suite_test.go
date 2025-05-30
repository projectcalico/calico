package codec_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"
)

func setupTest(t *testing.T) {
	RegisterTestingT(t)
}

func NoopURLVarsFunc(r *http.Request) map[string]string {
	return map[string]string{}
}
