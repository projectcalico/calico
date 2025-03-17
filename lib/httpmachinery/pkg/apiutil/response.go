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

type ResponseWriter interface {
	WriteResponse(apicontext.Context, int, http.ResponseWriter) error
}

type baseResponse struct {
	status int
	errMsg string
}

func (r baseResponse) Status() int {
	return r.status
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// List represents a generic list response. It includes the total number of items that would have been returned if
// limits / offsets weren't applied.
type List[E any] struct {
	// Total is the total number of items that would have been returned if limits and offsets weren't applied.
	Total int `json:"total"`
	Items []E `json:"items"`
}

// ListResponse implements the ResponseWriter and writes the response as a list with a total number of items that would
// have been returned if limits / offsets weren't applied.
type ListResponse[E any] struct {
	baseResponse
	rsp List[E]
}

func NewListResponse[E any]() ListResponse[E] {
	return ListResponse[E]{}
}

func (l ListResponse[E]) SetStatus(status int) ListResponse[E] {
	l.status = status
	return l
}

func (l ListResponse[E]) SetError(err string) ListResponse[E] {
	l.errMsg = err
	return l
}

func (l ListResponse[E]) SetItems(total int, items []E) ListResponse[E] {
	l.rsp.Total = total
	l.rsp.Items = items
	return l
}

// ResponseWriter returns a ResponseWriter to write the https response as a list. Currently, the response is written
// as a json list.
func (l ListResponse[E]) ResponseWriter() ResponseWriter {
	if l.errMsg != "" {
		return &jsonErrorResponseWriter{l.errMsg}
	}

	return &jsonListResponseWriter[E]{items: List[E]{Total: l.rsp.Total, Items: l.rsp.Items}}
}

// ListOrStreamResponse implements the ResponseWriter and writes the response as either a stream or a list, depending
// on whether SendStream or SendList was called.
type ListOrStreamResponse[E any] struct {
	baseResponse
	responseWriter ResponseWriter
}

func NewListOrStreamResponse[E any]() ListOrStreamResponse[E] {
	return ListOrStreamResponse[E]{}
}

func (rsp ListOrStreamResponse[E]) SetStatus(status int) ListOrStreamResponse[E] {
	rsp.status = status
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetError(err string) ListOrStreamResponse[E] {
	rsp.errMsg = err
	return rsp
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

func (rsp ListOrStreamResponse[E]) ResponseWriter() ResponseWriter {
	if err := rsp.errMsg; err != "" {
		return &jsonErrorResponseWriter{err}
	}

	return rsp.responseWriter
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
