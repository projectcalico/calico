package handler

import (
	"encoding/json"
	"net/http"

	_ctx "github.com/projectcalico/calico/lib/httpapimachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/header"
	"github.com/sirupsen/logrus"
)

// handler is an unexported http.Handler, used to force APIs to get the handler implementations from this package and
// implement missing handlers here. These handlers are responsible for reading the request, decoding them into concreate
// objects to pass to some "backend" handler, retrieves the response from the backend handlers and encodes the response
// properly. This abstracts out all http request / response handling logic from the backend implementation.
type handler http.Handler

func NewBasicJSONHandler[RequestParams any, Body any](f func(_ctx.Context, RequestParams) ResponseType[Body]) handler {
	return genericJSONHandler[RequestParams, Body]{
		f: f,
	}
}

func NewJSONListResponseHandler[RequestParams any, Body any](f func(_ctx.Context, RequestParams) ListResponse[Body]) handler {
	return genericJSONHandler[RequestParams, List[Body]]{
		f: func(ctx _ctx.Context, r RequestParams) ResponseType[List[Body]] {
			return ResponseType[List[Body]](f(ctx, r))
		},
	}
}

// genericJSONHandler is a handler that accepts either no body or a json body in the request and response with a json
// object. If the api needs to accept lists of objects or respond with them then this is not suitable, use something like
// ndJSONReqRespHandler or ndJSONRespHandler.
type genericJSONHandler[RequestParams any, Body any] struct {
	f func(_ctx.Context, RequestParams) ResponseType[Body]
}

func (g genericJSONHandler[RequestParams, Response]) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	params := parseRequestParams[RequestParams](w, req)
	if params == nil {
		return
	}
	ctx := _ctx.NewRequestContext(req)
	rsp := g.f(ctx, *params)
	if len(rsp.errMsg) > 0 {
		writeJSONError(w, rsp.status, rsp.errMsg)
	} else {
		w.WriteHeader(rsp.status)
		writeJSONResponse(w, rsp.body)
	}
}

func writeJSONResponse(w http.ResponseWriter, src any) {
	w.Header().Set(header.ContentType, header.ApplicationJSON)
	if err := json.NewEncoder(w).Encode(src); err != nil {
		logrus.WithError(err).Error("Failed to encode response.")
	}
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	writeJSONResponse(w, ErrorResponse{ErrMsg: message})
}
