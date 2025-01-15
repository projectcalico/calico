package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	_ctx "github.com/projectcalico/calico/lib/httpapimachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
)

func TestFlowLogsEventStream(t *testing.T) {
	setupTest(t)

	type Request struct{}
	type Response struct {
		Field string `json:"foo"`
	}

	hdlr := handler.NewJSONEventStreamHandler(func(ctx _ctx.Context, params Request, stream handler.EventStream[Response]) {
		Expect(stream.Data(Response{Field: "bar"})).ShouldNot(HaveOccurred())
		Expect(stream.Data(Response{Field: "baz"})).ShouldNot(HaveOccurred())

		return
	})

	w := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "foobar", bytes.NewBufferString(mustMarshal(Request{})))
	Expect(err).NotTo(HaveOccurred())

	hdlr.ServeHTTP(w, r)

	Expect(w.Code).To(Equal(http.StatusOK))
	Expect(w.Body.String()).To(Equal(fmt.Sprintf("data: %s\n\ndata: %s\n\n",
		mustMarshal(Response{Field: "bar"}), mustMarshal(Response{Field: "baz"}))))
}

func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func mustUnmarshal[E any](str []byte) *E {
	e := new(E)

	if err := json.Unmarshal(str, e); err != nil {
		panic(err)
	}
	return e
}
