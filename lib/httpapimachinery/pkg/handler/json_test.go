package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	_ctx "github.com/projectcalico/calico/lib/httpapimachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
)

func TestJSONListResponse(t *testing.T) {
	setupTest(t)

	type Request struct {
		ReqField string `urlQuery:"reqField"`
	}
	type Response struct {
		RespField string `json:"rspField"`
	}

	hdlr := handler.NewJSONListResponseHandler(func(ctx _ctx.Context, params Request) handler.ListResponse[Response] {
		Expect(params.ReqField).To(Equal("value"))
		return handler.NewListResponse[Response](http.StatusOK).SetTotal(20).SetItems([]Response{
			{RespField: "foo"},
			{RespField: "bar"},
		})
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", nil)
	Expect(err).NotTo(HaveOccurred())

	values := r.URL.Query()
	values.Set("reqField", "value")
	r.URL.RawQuery = values.Encode()

	hdlr.ServeHTTP(w, r)

	type ListResponse struct {
		Items []Response `json:"items"`
		Total int        `json:"total"`
	}

	Expect(mustUnmarshal[ListResponse](w.Body.Bytes())).To(Equal(&ListResponse{
		Items: []Response{
			{RespField: "foo"},
			{RespField: "bar"},
		},
		Total: 20,
	}))
}
