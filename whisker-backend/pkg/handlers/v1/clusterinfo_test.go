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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/testutil"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
	hdlrv1 "github.com/projectcalico/calico/whisker-backend/pkg/handlers/v1"
	clientmocks "github.com/projectcalico/calico/whisker-backend/pkg/test/thirdpartymocks/sigs.k8s.io/controller-runtime/pkg/client"
)

func TestUsageGet(t *testing.T) {
	sc := setupTest(t)

	t.Run("successful get", func(t *testing.T) {
		mockedExpectedClusterInfo := &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: apiv3.ClusterInformationSpec{
				ClusterGUID:   "1234",
				ClusterType:   "k8s",
				CalicoVersion: "v3.17.0",
			},
		}
		mockClient := new(clientmocks.Client)
		mockClient.On("Get", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			objectKey := args.Get(1).(ctrlclient.ObjectKey)
			Expect(objectKey.Name).To(Equal("default"))
			arg := args.Get(2).(*apiv3.ClusterInformation)
			Expect(arg.ObjectMeta.Name).To(Equal("default"))
			arg.Spec = mockedExpectedClusterInfo.Spec
		}).Return(nil)

		hdlr := hdlrv1.NewClusterInfoHandler(mockClient)
		rsp := hdlr.Get(sc.apiCtx, whiskerv1.ClusterInfoParams{})
		Expect(rsp.Status()).Should(Equal(http.StatusOK))
		recorder := httptest.NewRecorder()
		Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusOK, recorder)).ShouldNot(HaveOccurred())

		actualClusterInfo := testutil.MustUnmarshal[whiskerv1.ClusterInfoResponse](t, recorder.Body.Bytes())
		Expect(actualClusterInfo.CalicoVersion).Should(
			Equal(mockedExpectedClusterInfo.Spec.CalicoVersion))
		Expect(actualClusterInfo.ClusterGUID).Should(
			Equal(mockedExpectedClusterInfo.Spec.ClusterGUID))
		Expect(actualClusterInfo.ClusterType).Should(
			Equal(mockedExpectedClusterInfo.Spec.ClusterType))
	})

	t.Run("failed get", func(t *testing.T) {
		mockClient := new(clientmocks.Client)
		mockClient.On("Get", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("some error"))

		hdlr := hdlrv1.NewClusterInfoHandler(mockClient)
		rsp := hdlr.Get(sc.apiCtx, whiskerv1.ClusterInfoParams{})
		Expect(rsp.Status()).Should(Equal(http.StatusInternalServerError))
		recorder := httptest.NewRecorder()
		Expect(rsp.ResponseWriter().WriteResponse(sc.apiCtx, http.StatusInternalServerError, recorder)).ShouldNot(HaveOccurred())
	})
}
