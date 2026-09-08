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

type healthHdlr struct{}

func NewHealth() *healthHdlr {
	return &healthHdlr{}
}

func (hdlr *healthHdlr) APIs() []apiutil.Endpoint {
	return []apiutil.Endpoint{
		{
			Method:  http.MethodGet,
			Path:    whiskerv1.HealthPath,
			Handler: apiutil.NewJSONHandler(hdlr.Health),
		},
	}
}

// Health reports that the server is live and able to serve HTTP requests. A k8s liveness probe can use this to
// detect and restart a hung process.
func (hdlr *healthHdlr) Health(ctx apictx.Context, _ struct{}) apiutil.ObjectResponse[whiskerv1.HealthStatusResponse] {
	return apiutil.NewObjectResponse[whiskerv1.HealthStatusResponse]().
		SetStatus(http.StatusOK).
		SetBody(whiskerv1.HealthStatusResponse{Status: "ok"})
}
