// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	fsCli := new(climocks.FlowsClient)
	fsCli.On("List", mock.Anything, mock.Anything).Return([]*proto.FlowResult{
		{
			Flow: &proto.Flow{
				Key: &proto.FlowKey{
					SourceNamespace: "default",
					SourceName:      "test-pod",
				},
			},
		},
	}, nil)

	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))
	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	flows := testutil.MustUnmarshal[apiutil.List[whiskerv1.FlowResponse]](t, recorder.Body.Bytes())
	Expect(flows).Should(
		Equal(&apiutil.List[whiskerv1.FlowResponse]{
			Total: 1,
			Items: []whiskerv1.FlowResponse{
				{
					StartTime:       sc.zeroTime,
					EndTime:         sc.zeroTime,
					SourceNamespace: "default",
					SourceName:      "test-pod",
				},
			},
		}))
}

func TestWatchFlows(t *testing.T) {
	sc := setupTest(t)

	fsCli := new(climocks.FlowsClient)
	flowStream := new(protomock.Flows_StreamClient[proto.FlowResult])

	flowStream.On("Recv").Return(&proto.FlowResult{
		Flow: &proto.Flow{
			Key: &proto.FlowKey{
				SourceNamespace: "default",
				SourceName:      "test-pod",
			},
		},
	}, nil).Once()
	flowStream.On("Recv").Return(nil, io.EOF).Once()

	fsCli.On("Stream", mock.Anything, mock.Anything).Return(flowStream, nil)
	hdlr := hdlrv1.NewFlows(fsCli)
	rsp := hdlr.ListOrStream(sc.apiCtx, whiskerv1.ListFlowsParams{Watch: true})
	Expect(rsp.Status()).Should(Equal(http.StatusOK))

	recorder := httptest.NewRecorder()
	Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

	var flows []whiskerv1.FlowResponse
	for _, data := range strings.Split(recorder.Body.String(), "\n\n") {
		if len(data) == 0 {
			continue
		}

		flow := testutil.MustUnmarshal[whiskerv1.FlowResponse](t, []byte(strings.TrimPrefix(data, "data: ")))
		flows = append(flows, *flow)
	}

	expected := []whiskerv1.FlowResponse{
		{
			StartTime:       sc.zeroTime,
			EndTime:         sc.zeroTime,
			SourceNamespace: "default",
			SourceName:      "test-pod",
		},
	}
	Expect(flows).Should(Equal(expected))
}
