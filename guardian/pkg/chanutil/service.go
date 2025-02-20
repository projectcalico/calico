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

import (
	"context"
	"errors"
	"sync"
)

// TODO maybe this shouldn't be under a "chan" package, but some sort of "service" package? The channel isn't actually exposed...
type Service[Req any, Resp any] interface {
	Send(req Req) (Resp, error)
	Listen() <-chan Request[Req, Resp]
	Close()
}

type service[Req any, Resp any] struct {
	ch chan Request[Req, Resp]
}

func NewService[Req any, Resp any](bufferSize int) Service[Req, Resp] {
	return &service[Req, Resp]{ch: make(chan Request[Req, Resp], bufferSize)}
}

func (srv *service[Req, Resp]) Send(req Req) (Resp, error) {
	rspChan := make(chan ResponseType[Resp])

	// TODO should we add the timeout back in?
	srv.ch <- Request[Req, Resp]{req: req, rspChan: rspChan}
	// TODO need to ensure some other kind of timeout... maybe??
	rsp := <-rspChan
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
	Add(Request[Req, Resp])
	Fire()
	WaitForShutdown()
}

type reqsHandler[Req any, Resp any] struct {
	handleFunc     func(context.Context, Req) (Resp, error)
	errors         *SyncedError
	shutdownCtx    context.Context
	requestChan    chan Request[Req, Resp]
	failedReqsChan chan Request[Req, Resp]
	fire           chan struct{}
	inflightReqs   sync.WaitGroup
}

func (h *reqsHandler[Req, Resp]) WaitForShutdown() {
	h.inflightReqs.Wait()
}

func (h *reqsHandler[Req, Resp]) Fire() {
	h.fire <- struct{}{}
}

func (h *reqsHandler[Req, Resp]) Add(req Request[Req, Resp]) {
	h.requestChan <- req
}

// NewRequestsHandler creates a new RequestHandler implementation.
func NewRequestsHandler[Req any, Resp any](ctx context.Context, errors *SyncedError, f func(context.Context, Req) (Resp, error)) RequestsHandler[Req, Resp] {
	hdlr := &reqsHandler[Req, Resp]{
		handleFunc:     f,
		errors:         errors,
		requestChan:    make(chan Request[Req, Resp], 100),
		failedReqsChan: make(chan Request[Req, Resp], 100),
		fire:           make(chan struct{}),
	}

	go hdlr.loop(ctx)
	return hdlr
}

func (h *reqsHandler[Req, Resp]) loop(ctx context.Context) {
	var requests, failedRequests []Request[Req, Resp]
	defer close(h.requestChan)
	defer close(h.fire)

	for {
		select {
		case <-ctx.Done():
			h.errors.Send(ctx.Err())
			return
		case req := <-h.requestChan:
			requests = append(requests, req)
		case req := <-h.failedReqsChan:
			failedRequests = append(failedRequests, req)
		case <-h.fire:
			requests = append(failedRequests, requests...)
			failedRequests = nil

			for _, req := range requests {
				h.handleRequest(ctx, req)
			}

			requests = nil
		}
	}
}

func (h *reqsHandler[Req, Resp]) handleRequest(ctx context.Context, req Request[Req, Resp]) {
	h.inflightReqs.Add(1)
	go func() {
		defer h.inflightReqs.Done()
		rsp, err := h.handleFunc(ctx, req.Get())
		if err != nil {
			h.errors.Send(err)

			if errors.Is(err, context.Canceled) {
				req.ReturnError(err)
				req.Close()
				return
			}

			h.failedReqsChan <- req

			return
		}

		req.Return(rsp)
		req.Close()
	}()
}
