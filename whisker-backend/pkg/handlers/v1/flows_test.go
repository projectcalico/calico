package v1_test

import (
	"io"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	climocks "github.com/projectcalico/calico/goldmane/pkg/client/mocks"
	"github.com/projectcalico/calico/goldmane/proto"
	protomock "github.com/projectcalico/calico/goldmane/proto/mocks"
	apictxmocks "github.com/projectcalico/calico/lib/httpmachinery/pkg/context/mocks"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
)

func TestListFlows(t *testing.T) {
	setupTest(t)

	ctx := new(apictxmocks.Context)
	ctx.On("Logger").Return(logrus.NewEntry(logrus.StandardLogger()), "")

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
	rsp := hdlr.List(ctx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Error()).Should(BeEmpty())
	Expect(rsp.Items()).Should(Equal([]whiskerv1.FlowResponse{
		{
			StartTime:       time.Unix(0, 0),
			EndTime:         time.Unix(0, 0),
			SourceNamespace: "default",
			SourceName:      "test-pod",
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
	rsp := hdlr.List(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})

	var flows []whiskerv1.FlowResponse

	for flow := range rsp.Itr() {
		flows = append(flows, flow)
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
