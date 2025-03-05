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

package v1

import (
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"

	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type clusterInfoHdlr struct {
	client ctrlclient.Client
}

func NewClusterInfoHandler(cli ctrlclient.Client) *clusterInfoHdlr {
	return &clusterInfoHdlr{client: cli}
}

func (hdlr *clusterInfoHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.ClusterInfoPath,
			Handler: apiutil.NewJSONSingleResponseHandler(hdlr.Get),
		},
	}
}

func (hdlr *clusterInfoHdlr) Get(ctx apictx.Context, params whiskerv1.ClusterInfoParams) apiutil.SingleResponse[whiskerv1.ClusterInfoResponse] {
	logger := ctx.Logger()
	logger.Debug("Get Cluster called.")
	if params.Name == "" {
		params.Name = "default"
	}
	clusterInfo := &apiv3.ClusterInformation{ObjectMeta: metav1.ObjectMeta{Name: params.Name}}

	err := hdlr.client.Get(ctx, ctrlclient.ObjectKeyFromObject(clusterInfo), clusterInfo)
	if err != nil {
		logger.Error("Failed to get ClusterInformation: ", err)
		return apiutil.NewSingleResponse[whiskerv1.ClusterInfoResponse](http.StatusInternalServerError).SetError("Internal Server Error")
	}

	return apiutil.NewSingleResponse[whiskerv1.ClusterInfoResponse](http.StatusOK).Send(whiskerv1.ClusterInfoResponse{ClusterGUID: clusterInfo.Spec.ClusterGUID, ClusterType: clusterInfo.Spec.ClusterType, CalicoVersion: clusterInfo.Spec.CalicoVersion})
}
