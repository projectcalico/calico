// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/calico/lib/httpmachinery/pkg/apiutil"
	apictx "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	whiskerv1 "github.com/projectcalico/calico/whisker-backend/pkg/apis/v1"
)

type configHdlr struct {
	streaming bool
}

func NewConfig(streaming bool) *configHdlr {
	return &configHdlr{streaming: streaming}
}

func (hdlr *configHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.ConfigPath,
			Handler: apiutil.NewJSONListHandler(hdlr.GetConfig),
		},
	}
}

func (hdlr *configHdlr) GetConfig(ctx apictx.Context, _ whiskerv1.ConfigRequest) apiutil.ListResponse[whiskerv1.ConfigResponse] {
	ctx.Logger().Debug("GetConfig called.")
	return apiutil.NewListResponse[whiskerv1.ConfigResponse]().
		SetStatus(http.StatusOK).
		SetItems([]whiskerv1.ConfigResponse{
			{Streaming: hdlr.streaming},
		})
}
