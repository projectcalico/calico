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

package chanutil

import "context"

// TODO maybe this shouldn't be under a "chan" package, but some sort of "service" package? The channel isn't actually exposed...
type Service[Req any, Resp any] interface {
	Send(ctx context.Context, req Req) (Resp, error)
	Listen() <-chan Request[Req, Resp]
	Close()
}

type service[Req any, Resp any] struct {
	ch chan Request[Req, Resp]
}

func NewService[Req any, Resp any](bufferSize int) Service[Req, Resp] {
	return &service[Req, Resp]{ch: make(chan Request[Req, Resp], bufferSize)}
}

func (srv *service[Req, Resp]) Send(ctx context.Context, req Req) (Resp, error) {
	rspChan := make(chan ResponseType[Resp])

	select {
	case <-ctx.Done():
	case srv.ch <- Request[Req, Resp]{req: req, rspChan: rspChan}:
	}

	// TODO need to ensure some other kind of timeout... maybe??
	var rsp ResponseType[Resp]
	select {
	case rsp = <-rspChan:
	case <-ctx.Done():
		return rsp.resp, ctx.Err()
	}
	return rsp.resp, rsp.err
}

func (srv *service[Req, Resp]) Listen() <-chan Request[Req, Resp] {
	return srv.ch
}

func (srv *service[Req, Resp]) Close() {
	close(srv.ch)
}

type ResponseType[Resp any] struct {
	resp Resp
	err  error
}

type Request[Req any, Resp any] struct {
	req     Req
	rspChan chan ResponseType[Resp]
}

func (c Request[Req, Resp]) Get() Req {
	return c.req
}

func (c Request[Req, Resp]) Return(resp Resp) {
	c.rspChan <- ResponseType[Resp]{resp: resp}
}

func (c Request[Req, Resp]) Close() {
	close(c.rspChan)
}

func (c Request[Req, Resp]) ReturnError(err error) {
	c.rspChan <- ResponseType[Resp]{err: err}
}

type RequestsHandler[Req any, Resp any] interface {
	Handle() error
	ReturnError(error)
	Close()
	Add(Request[Req, Resp])
}

type reqsHandler[Req any, Resp any] struct {
	requests   []Request[Req, Resp]
	handleFunc func(Req) (Resp, error)
}

func (h *reqsHandler[Req, Resp]) ReturnError(err error) {
	for _, req := range h.requests {
		req.ReturnError(err)
		req.Close()
	}
}

func (h *reqsHandler[Req, Resp]) Close() {
	for _, req := range h.requests {
		req.Close()
	}
}
func (h *reqsHandler[Req, Resp]) Handle() error {
	for i, req := range h.requests {
		rsp, err := h.handleFunc(req.Get())
		if err != nil {
			h.requests = h.requests[i:]
			return err
		}

		req.Return(rsp)
		req.Close()
	}

	h.requests = nil
	return nil
}

func (h *reqsHandler[Req, Resp]) Add(req Request[Req, Resp]) {
	h.requests = append(h.requests, req)
}

func NewRequestsHandler[Req any, Resp any](f func(Req) (Resp, error)) RequestsHandler[Req, Resp] {
	return &reqsHandler[Req, Resp]{handleFunc: f}
}
