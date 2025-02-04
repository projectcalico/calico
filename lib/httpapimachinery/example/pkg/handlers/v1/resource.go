package v1

import (
	"context"
	"net/http"

	v1 "github.com/projectcalico/calico/lib/httpapimachinery/example/pkg/apis/v1"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
)

type flows struct{}

func (r *flows) APIs() []handler.API {
	return []handler.API{
		{
			Method:  http.MethodGet,
			URL:     v1.ResourcesPath,
			Handler: handler.NewNDJSONRespHandler(r.List),
		},
		{
			Method:  http.MethodGet,
			URL:     v1.ResourcePath,
			Handler: handler.NewBasicJSONHandler(r.Get),
		},
	}
}

func (r *flows) Get(ctx context.Context, params v1.GetResourceParams) handler.ResponseType[v1.GetResourceResponse] {
	return handler.ResponseType[v1.GetResourceResponse]{}
}

func (r *flows) List(ctx context.Context, params v1.ListResourceParams) []handler.ResponseType[v1.GetResourceResponse] {
	return []handler.ResponseType[v1.GetResourceResponse]{}
}
