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

type ErrorResponse struct {
	Error string `json:"error"`
}

// ResponseType is an object that APIs return for the generic handlers to respond with. It's up to the generic handlers
// to decide how they handle errors and the status as well as format the Body returned (i.e. JSON, CSV, other...).
// This helps abstract http response logic / formatting from the API implementations.
type ResponseType[E any] struct {
	// Headers are the addition headers to response with.
	headers map[string]string
	status  int
	errMsg  string
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
	rsp.errMsg = msg
	return rsp
}

func NewResponse[E any](code int) ResponseType[E] {
	return ResponseType[E]{
		headers: make(map[string]string),
		status:  code,
	}
}

type List[E any] struct {
	Total int `json:"total"`
	Items []E `json:"items"`
}

func NewListResponse[E any](status int) ListResponse[E] {
	return ListResponse[E]{
		headers: make(map[string]string),
		status:  status,
		body:    List[E]{},
	}
}

type ListResponse[E any] ResponseType[List[E]]

func (rsp ListResponse[E]) SetItems(items []E) ListResponse[E] {
	rsp.body.Items = items
	return rsp
}

func (rsp ListResponse[E]) SetTotal(total int) ListResponse[E] {
	rsp.body.Total = total
	return rsp
}

func (rsp ListResponse[E]) SetErrorMsg(msg string) ListResponse[E] {
	rsp.errMsg = msg
	return rsp
}
