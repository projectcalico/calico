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
	"io"
	"sync"

	"github.com/sirupsen/logrus"
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
	defer close(c.rspChan)
	c.rspChan <- ResponseType[Resp]{resp: resp}
}

//func (c Request[Req, Resp]) Close() {
//	close(c.rspChan)
//}

func (c Request[Req, Resp]) ReturnError(err error) {
	defer close(c.rspChan)
	c.rspChan <- ResponseType[Resp]{err: err}
}

type RequestsHandler[Req any, Resp any] interface {
	Add(Request[Req, Resp])
	Fire()
	StopAndRequeueRequests()
	WaitForShutdown()
}

type RequestsHandlers []interface {
	Fire()
	StopAndRequeueRequests()
	WaitForShutdown()
}

func (hdlrs RequestsHandlers) Fire() {
	for _, h := range hdlrs {
		h.Fire()
	}
}

func (hdlrs RequestsHandlers) StopAndRequeueRequests() {
	for _, h := range hdlrs {
		h.StopAndRequeueRequests()
	}
}

func (hdlrs RequestsHandlers) WaitForShutdown() {
	for _, h := range hdlrs {
		h.WaitForShutdown()
	}
}

type reqsHandler[Req any, Resp any] struct {
	handleFunc      func(context.Context, Req) (Resp, error)
	requeueRequests chan chan struct{}
	requestChan     chan Request[Req, Resp]
	inflightReqs    sync.WaitGroup
	fire            chan struct{}
	done            chan struct{}
	requestErrors   chan error
}

func (h *reqsHandler[Req, Resp]) WaitForShutdown() {
	<-h.done
}

func (h *reqsHandler[Req, Resp]) Fire() {
	h.fire <- struct{}{}
}

func (h *reqsHandler[Req, Resp]) Add(req Request[Req, Resp]) {
	h.requestChan <- req
}

// NewRequestsHandler creates a new RequestHandler implementation.
func NewRequestsHandler[Req any, Resp any](ctx context.Context, requestErrors chan error, f func(context.Context, Req) (Resp, error)) RequestsHandler[Req, Resp] {
	hdlr := &reqsHandler[Req, Resp]{
		handleFunc:      f,
		requestErrors:   requestErrors,
		requestChan:     make(chan Request[Req, Resp], 100),
		requeueRequests: make(chan chan struct{}),

		fire: make(chan struct{}),
		done: make(chan struct{}),
	}

	go hdlr.loop(ctx)
	return hdlr
}

func (h *reqsHandler[Req, Resp]) loop(shutdownCtx context.Context) {
	var requests []Request[Req, Resp]
	defer close(h.requestChan)
	defer close(h.fire)
	ctx, stopRequests := context.WithCancel(shutdownCtx)
	defer func() {
		defer stopRequests()
		defer close(h.done)

		logrus.Debug("Deferring stuff")

		for _, req := range requests {
			req.ReturnError(context.Canceled)
		}

		logrus.Debug("Finished deferring stuff")
	}()

	for {
		select {
		case <-shutdownCtx.Done():
			logrus.Debug("Shutting down")
			return
		case req := <-h.requestChan:
			requests = append(requests, req)
		case notify := <-h.requeueRequests:
			stopRequests()
			go func() {
				defer close(notify)
				h.inflightReqs.Wait()
			}()
		case <-h.fire:
			requests = append(requests, ReadBatch(h.requestChan, 100)...)
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
			WriteNoWait(h.requestErrors, err)
			if errors.Is(err, io.EOF) {
				h.requestChan <- req
				return
			}

			req.ReturnError(err)
			return
		}

		req.Return(rsp)
	}()
}

func (h *reqsHandler[Req, Resp]) StopAndRequeueRequests() {
	notify := make(chan struct{})
	h.requeueRequests <- notify
	<-notify

	// At this point there are no outstanding requests so clear any built up errors.
	Clear(h.requestErrors)
}
