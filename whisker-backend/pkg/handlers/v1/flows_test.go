package v1_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	climocks "github.com/projectcalico/calico/goldmane/pkg/client/mocks"
	"github.com/projectcalico/calico/goldmane/proto"
	protomock "github.com/projectcalico/calico/goldmane/proto/mocks"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestListFlows(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowServiceClient)
	fsCli.On("List", mock.Anything, mock.Anything).Return([]*proto.Flow{
		{
			Key: &proto.FlowKey{
				SourceNamespace: "default",
				SourceName:      "test-pod",
			},
		},
	}, nil)

	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, recorder)).ShouldNot(HaveOccurred())
	Expect(testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())).Should(
		Equal(&apiutil.List[whiskerv1.FlowResponse]{
			Total: 1,
			Items: []whiskerv1.FlowResponse{
				{
					StartTime:       time.Unix(0, 0),
					EndTime:         time.Unix(0, 0),
					SourceNamespace: "default",
					SourceName:      "test-pod",
				},
			},
		}))
}

func TestWatchFlows(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowServiceClient)
	flowStream := new(protomock.FlowAPI_StreamClient[proto.Flow])

	flowStream.On("Recv").Return(&proto.Flow{
		Key: &proto.FlowKey{
			SourceNamespace: "default",
			SourceName:      "test-pod",
		},
	}, nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()

	fsCli.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)
	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, recorder)).ShouldNot(HaveOccurred())

	var flows []whiskerv1.FlowResponse
	for _, data := range strings.Split(recorder.Body.String(), "\n\n") {
		if len(data) == 0 {
			continue
		}
		flow := testutil.MustUnmarshal[whiskerv1.FlowResponse](t, []byte(strings.TrimPrefix(data, "data: ")))
		flows = append(flows, *flow)
	}

	Expect(flows).Should(Equal([]whiskerv1.FlowResponse{
		{
			StartTime:       time.Unix(0, 0),
			EndTime:         time.Unix(0, 0),
			SourceNamespace: "default",
			SourceName:      "test-pod",
		},
	}))
}
