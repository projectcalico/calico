package v1_test

import (
	"net/http"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	apicontextmocks "github.com/projectcalico/calico/lib/httpmachinery/pkg/context/mocks"
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
	ctx.On("Logger").Return(logrus.NewEntry(logrus.StandardLogger()), "")

	return scaffold{
		apiCtx: ctx,
	}
}
