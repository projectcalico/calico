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

import "iter"

type ErrorResponse struct {
	Error string `json:"error"`
}

type ListOrStream[E any] struct {
	Lister *List[E]

	Streamer *Streamer[E]
}

type List[E any] struct {
	Total int `json:"total"`
	Items []E `json:"items"`
}

type Streamer[E any] struct {
	Stream iter.Seq[E]
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

func (rsp ListOrStreamResponse[E]) SendList(total int, items []E) ListOrStreamResponse[E] {
	if rsp.responseWriter != nil {
		panic("response writer already set")
	}

	rsp.responseWriter = &jsonListResponseWriter[E]{items: List[E]{Total: total, Items: items}}
	return rsp
}

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
