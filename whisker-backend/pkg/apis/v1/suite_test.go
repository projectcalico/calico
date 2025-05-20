package v1_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"

	apicontextmocks "github.com/projectcalico/calico/lib/httpmachinery/pkg/context/mocks"
	"github.com/projectcalico/calico/lib/std/log"
)

type scaffold struct {
	apiCtx *apicontextmocks.Context
}

func (sc scaffold) URLVars(*http.Request) map[string]string {
	return map[string]string{}
}

func setupTest(t *testing.T) scaffold {
	RegisterTestingT(t)

	ctx := new(apicontextmocks.Context)
	ctx.On("Logger").Return(log.NewEntry(log.StandardLogger()), "")

	return scaffold{
		apiCtx: ctx,
	}
}
