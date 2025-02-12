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

package apiutil

import (
	"iter"
	"net/http"

	apicontext "github.com/projectcalico/calico/lib/httpmachinery/pkg/context"
	"github.com/projectcalico/calico/lib/httpmachinery/pkg/header"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type List[E any] struct {
	Total int `json:"total"`
	Items []E `json:"items"`
}

type ListOrStreamResponse[E any] struct {
	status         int
	responseWriter ResponseWriter
}

func NewListOrStreamResponse[E any](status int) ListOrStreamResponse[E] {
	return ListOrStreamResponse[E]{
		status: status,
	}
}

// SendList sets the ListOrStreamResponse to send back a list with the given total and items.
//
// If this is called, it is not valid to call this again or to call SendStream, those actions will result in a panic.
func (rsp ListOrStreamResponse[E]) SendList(total int, items []E) ListOrStreamResponse[E] {
	if rsp.responseWriter != nil {
		panic("response writer already set")
	}

	rsp.responseWriter = &jsonListResponseWriter[E]{items: List[E]{Total: total, Items: items}}
	return rsp
}

// SendStream sets the ListOrStreamResponse to send back a stream with the given iter.Seq. It will iterate through the
// objects given to it in the iterator and send them over the stream.
//
// If this is called, it is not valid to call this again or to call SendList, those actions will result in a panic.
func (rsp ListOrStreamResponse[E]) SendStream(itr iter.Seq[E]) ListOrStreamResponse[E] {
	if rsp.responseWriter != nil {
		panic("response writer already set")
	}

	rsp.responseWriter = &eventStreamResponseWriter[E]{items: itr}
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetError(msg string) ListOrStreamResponse[E] {
	rsp.responseWriter = &jsonErrorResponseWriter{msg}
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetStatus(status int) ListOrStreamResponse[E] {
	rsp.status = status
	return rsp
}

func (rsp ListOrStreamResponse[E]) ResponseWriter() ResponseWriter {
	return rsp.responseWriter
}

func (rsp ListOrStreamResponse[E]) Status() int {
	return rsp.status
}

type ResponseWriter interface {
	WriteResponse(apicontext.Context, int, http.ResponseWriter) error
}

// eventStreamResponseWriter is used to respond with a server side event stream.
type eventStreamResponseWriter[Body any] struct {
	items iter.Seq[Body]
}

func (rs *eventStreamResponseWriter[Body]) WriteResponse(ctx apicontext.Context, status int, w http.ResponseWriter) error {
	w.Header().Set(header.ContentType, header.TextEventStream)
	w.Header().Set(header.CacheControl, header.NoCache)
	w.Header().Set(header.Connection, header.KeepAlive)
	w.WriteHeader(status)

	w.(http.Flusher).Flush()

	jStream := newJSONEventStreamWriter[Body](w)
	for item := range rs.items {
		if err := jStream.writeData(item); err != nil {
			ctx.Logger().WithError(err).Debug("Failed to write flow to stream.")
			return err
		}
	}

	return nil
}

// jsonListResponseWriter is used to write by a json list that contains the total.
type jsonListResponseWriter[Body any] struct {
	items List[Body]
}

func (rs *jsonListResponseWriter[Body]) WriteResponse(ctx apicontext.Context, status int, w http.ResponseWriter) error {
	w.WriteHeader(status)
	writeJSONResponse(w, rs.items)
	return nil
}

// jsonErrorResponseWriter is used to respond with a json error.
type jsonErrorResponseWriter struct {
	error string
}

func (rs *jsonErrorResponseWriter) WriteResponse(ctx apicontext.Context, status int, w http.ResponseWriter) error {
	writeJSONResponse(w, ErrorResponse{Error: rs.error})
	return nil
}
