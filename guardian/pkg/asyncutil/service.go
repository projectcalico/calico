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

package asyncutil

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

type CommandExecutor[Req any, Resp any] interface {
	Add(Command[Req, Resp])
	Execute()
	StopAndRequeueRequests()
	WaitForShutdown()
}

type CommandDispatcher []interface {
	Execute()
	StopAndRequeueRequests()
	WaitForShutdown()
}

func (dispatcher CommandDispatcher) Fire() {
	for _, executor := range dispatcher {
		executor.Execute()
	}
}

func (dispatcher CommandDispatcher) StopAndRequeueRequests() {
	for _, executor := range dispatcher {
		executor.StopAndRequeueRequests()
	}
}

func (dispatcher CommandDispatcher) WaitForShutdown() {
	for _, executer := range dispatcher {
		executer.WaitForShutdown()
	}
}

type executor[Req any, Resp any] struct {
	command           func(context.Context, Req) (Resp, error)
	stopAndRequeueSig chan chan struct{}
	cmdChan           chan Command[Req, Resp]
	inflightCmds      sync.WaitGroup
	executeSig        chan struct{}
	done              chan struct{}
	requestErrors     chan error
}

func (h *executor[Req, Resp]) WaitForShutdown() {
	<-h.done
}

func (h *executor[Req, Resp]) Execute() {
	h.executeSig <- struct{}{}
}

func (h *executor[Req, Resp]) Add(req Command[Req, Resp]) {
	h.cmdChan <- req
}

// NewRequestsHandler creates a new RequestHandler implementation.
func NewRequestsHandler[Req any, Resp any](ctx context.Context, cmdErrors chan error, f func(context.Context, Req) (Resp, error)) CommandExecutor[Req, Resp] {
	hdlr := &executor[Req, Resp]{
		command:           f,
		requestErrors:     cmdErrors,
		cmdChan:           make(chan Command[Req, Resp], 100),
		stopAndRequeueSig: make(chan chan struct{}),

		executeSig: make(chan struct{}),
		done:       make(chan struct{}),
	}

	go hdlr.loop(ctx)
	return hdlr
}

func (h *executor[C, R]) loop(shutdownCtx context.Context) {
	var cmds []Command[C, R]
	defer close(h.cmdChan)
	defer close(h.executeSig)
	ctx, stopRequests := context.WithCancel(shutdownCtx)
	defer func() {
		defer stopRequests()
		defer close(h.done)

		logrus.Debug("Deferring stuff")

		for _, req := range cmds {
			req.ReturnError(context.Canceled)
		}

		logrus.Debug("Finished deferring stuff")
	}()

	for {
		select {
		case <-shutdownCtx.Done():
			logrus.Debug("Shutting down")
			return
		case cmd := <-h.cmdChan:
			cmds = append(cmds, cmd)
		case notify := <-h.stopAndRequeueSig:
			stopRequests()
			go func() {
				defer close(notify)
				h.inflightCmds.Wait()
			}()
		case <-h.executeSig:
			cmds = append(cmds, ReadBatch(h.cmdChan, 100)...)
			for _, req := range cmds {
				h.handleRequest(ctx, req)
			}

			cmds = nil
		}
	}
}

func (h *executor[Req, Resp]) handleRequest(ctx context.Context, req Command[Req, Resp]) {
	h.inflightCmds.Add(1)
	go func() {
		defer h.inflightCmds.Done()
		rsp, err := h.command(ctx, req.Get())
		if err != nil {
			WriteNoWait(h.requestErrors, err)
			if errors.Is(err, io.EOF) {
				h.cmdChan <- req
				return
			}

			req.ReturnError(err)
			return
		}

		req.Return(rsp)
	}()
}

func (h *executor[Req, Resp]) StopAndRequeueRequests() {
	notify := make(chan struct{})
	h.stopAndRequeueSig <- notify
	<-notify

	// At this point there are no outstanding requests so clear any built up errors.
	Clear(h.requestErrors)
}
