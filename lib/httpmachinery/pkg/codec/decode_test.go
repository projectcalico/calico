package codec_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/codec"
	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
)

func TestRegisterCustomDecodeTypeFunc(t *testing.T) {
	setupTest(t)
	type stringType string

	type foo struct {
		URL    stringType `urlPath:"url"`
		Query  stringType `urlQuery:"query"`
		Header stringType `header:"X-Header"`
	}

	codec.RegisterCustomDecodeTypeFunc(func(vals []string) (stringType, error) {
		return stringType(vals[0] + "-decoded"), nil
	})

	req, err := http.NewRequest("GET", "http://example.com?query=query-value", nil)
	Expect(err).NotTo(HaveOccurred())

	req.Header.Set("X-Header", "header-value")

	param, err := codec.DecodeAndValidateRequestParams[foo](apicontext.NewRequestContext(req), func(r *http.Request) map[string]string {
		return map[string]string{"url": "url-value"}
	}, req)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(param.URL).To(Equal(stringType("url-value-decoded")))
	Expect(param.Query).To(Equal(stringType("query-value-decoded")))
	Expect(param.Header).To(Equal(stringType("header-value-decoded")))
}

func TestURLEncodedJSONDecoding(t *testing.T) {
	setupTest(t)

	type filter struct {
		Name string `json:"name"`
	}

	type params struct {
		Filter filter `urlQuery:"filter"`
	}

	codec.RegisterURLQueryJSONType[filter]()

	filterEncoded := url.QueryEscape(testutil.MustMarshal(t, filter{Name: "foo"}))

	req, err := http.NewRequest("GET", fmt.Sprintf("http://example.com?filter=%s", filterEncoded), nil)
	Expect(err).NotTo(HaveOccurred())

	param, err := codec.DecodeAndValidateRequestParams[params](apicontext.NewRequestContext(req), NoopURLVarsFunc, req)
	Expect(err).Should(Not(HaveOccurred()))
	Expect(param).Should(Equal(&params{Filter: filter{Name: "foo"}}))
}
