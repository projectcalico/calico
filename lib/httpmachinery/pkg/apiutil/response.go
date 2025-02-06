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

// ResponseType is an object that APIs return for the generic handlers to respond with. It's up to the generic handlers
// to decide how they handle errors and the status as well as format the Body returned (i.e. JSON, CSV, other...).
// This helps abstract http response logic / formatting from the API implementations.
type ResponseType[E any] struct {
	// Headers are the additional headers to response with.
	headers map[string]string
	status  int
	error   string
	body    E
}

func (rsp ResponseType[E]) SetStatus(status int) ResponseType[E] {
	rsp.status = status
	return rsp
}

func (rsp ResponseType[E]) AddHeader(name, value string) ResponseType[E] {
	rsp.headers[name] = value
	return rsp
}

func (rsp ResponseType[E]) SetErrorMsg(msg string) ResponseType[E] {
	rsp.error = msg
	return rsp
}

func NewResponse[E any](code int) ResponseType[E] {
	return ResponseType[E]{
		headers: make(map[string]string),
		status:  code,
	}
}

type ListOrStream[E any] struct {
	Lister *Lister[E]

	Streamer *Streamer[E]
}

type Lister[E any] struct {
	Total int `json:"total"`
	Items []E `json:"items"`
}

type Streamer[E any] struct {
	Stream iter.Seq[E]
}

type ListOrStreamResponse[E any] ResponseType[ListOrStream[E]]

func NewListOrStreamResponse[E any](status int) ListOrStreamResponse[E] {
	return ListOrStreamResponse[E]{
		headers: make(map[string]string),
		status:  status,
		body:    ListOrStream[E]{},
	}
}

func (rsp ListOrStreamResponse[E]) SetItems(items []E) ListOrStreamResponse[E] {
	if rsp.body.Streamer != nil {
		panic("cannot stream and list at the same time")
	}
	if rsp.body.Lister == nil {
		rsp.body.Lister = &Lister[E]{}
	}
	rsp.body.Lister.Items = items
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetTotal(total int) ListOrStreamResponse[E] {
	if rsp.body.Streamer != nil {
		panic("cannot stream and list at the same time")
	}
	if rsp.body.Lister == nil {
		rsp.body.Lister = &Lister[E]{}
	}
	rsp.body.Lister.Total = total
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetItr(itr iter.Seq[E]) ListOrStreamResponse[E] {
	if rsp.body.Lister != nil {
		panic("cannot stream and list at the same time")
	}
	if rsp.body.Streamer == nil {
		rsp.body.Streamer = &Streamer[E]{}
	}
	rsp.body.Streamer.Stream = itr
	return rsp
}

func (rsp ListOrStreamResponse[E]) SetErrorMsg(msg string) ListOrStreamResponse[E] {
	rsp.error = msg
	return rsp
}

func (rsp ListOrStreamResponse[E]) Itr() iter.Seq[E] {
	return rsp.body.Streamer.Stream
}

func (rsp ListOrStreamResponse[E]) Total() int {
	return rsp.body.Lister.Total
}

func (rsp ListOrStreamResponse[E]) Items() []E {
	return rsp.body.Lister.Items
}

func (rsp ListOrStreamResponse[E]) Error() string {
	return rsp.error
}
