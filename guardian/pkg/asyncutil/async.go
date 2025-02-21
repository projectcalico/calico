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

type CommandExecutor[C any, R any] interface {
	Send(C) <-chan Result[R]
	PauseExecution()
	ResumeExecution()
	ShutdownSignaler() Signaler
}

type CommandDispatcher []interface {
	PauseExecution()
	ResumeExecution()
	ShutdownSignaler() Signaler
}

func (dispatcher CommandDispatcher) PauseExecution() {
	for _, executor := range dispatcher {
		executor.PauseExecution()
	}
}

func (dispatcher CommandDispatcher) ResumeExecution() {
	for _, executor := range dispatcher {
		executor.ResumeExecution()
	}
}

func (dispatcher CommandDispatcher) WaitForShutdown() {
	for _, executor := range dispatcher {
		<-executor.ShutdownSignaler().Receive()
	}
}

type commandExecutor[Req any, Resp any] struct {
	command             func(context.Context, Req) (Resp, error)
	pauseExecution      chan chan struct{}
	resumeExecution     Signaler
	cmdChan             chan Command[Req, Resp]
	backlogChan         chan Command[Req, Resp]
	inflightCmds        sync.WaitGroup
	executeSig          Signaler
	shutdownCompleteSig Signaler
	errBuff             AsyncErrorBuffer
}

// NewCommandExecutor creates a new RequestHandler implementation.
func NewCommandExecutor[C any, R any](ctx context.Context, errBuff AsyncErrorBuffer, f func(context.Context, C) (R, error)) CommandExecutor[C, R] {
	hdlr := &commandExecutor[C, R]{
		command:         f,
		errBuff:         errBuff,
		cmdChan:         make(chan Command[C, R], 100),
		backlogChan:     make(chan Command[C, R], 100),
		pauseExecution:  make(chan chan struct{}),
		resumeExecution: NewSignaler(),

		executeSig:          NewSignaler(),
		shutdownCompleteSig: NewSignaler(),
	}

	go hdlr.loop(ctx)
	return hdlr
}

func (executor *commandExecutor[C, R]) Receive() <-chan Command[C, R] {
	return executor.cmdChan
}

func (executor *commandExecutor[C, R]) ShutdownSignaler() Signaler {
	return executor.shutdownCompleteSig
}

func (executor *commandExecutor[C, R]) Send(params C) <-chan Result[R] {
	cmd, resultChan := NewCommand[C, R](params)
	executor.cmdChan <- cmd
	return resultChan
}

func (executor *commandExecutor[C, R]) loop(shutdownCtx context.Context) {
	var backlog []Command[C, R]

	defer close(executor.cmdChan)
	defer close(executor.backlogChan)
	defer executor.executeSig.Close()
	defer close(executor.pauseExecution)
	defer executor.resumeExecution.Close()
	ctx, stopCommands := context.WithCancel(shutdownCtx)
	defer func() {
		defer stopCommands()
		defer executor.shutdownCompleteSig.Close()

		logrus.Debug("Returning errors for outstanding requests due to shutdown.")
		for _, req := range backlog {
			req.ReturnError(context.Canceled)
		}
		logrus.Debug("Finished returning errors for outstanding requests due to shutdown.")
	}()

	var pause bool
	for {
		select {
		case <-shutdownCtx.Done():
			logrus.Debug("Shutdown signal received, shutting down...")
			return
		case cmd := <-executor.cmdChan:
			logrus.Debugf("Received command.")
			if !pause {
				executor.executeCommand(ctx, cmd)
			} else {
				backlog = append(backlog, cmd)
			}
		case cmd := <-executor.backlogChan:
			backlog = append(backlog, cmd)
		case notify := <-executor.pauseExecution:
			logrus.Debugf("Received requeus signal.")
			pause = true
			stopCommands()
			go func() {
				defer close(notify)
				executor.inflightCmds.Wait()
				executor.errBuff.Clear()
			}()
		case <-executor.resumeExecution.Receive():
			// Handle the backlog before resuming execution.
			for _, cmd := range backlog {
				executor.executeCommand(ctx, cmd)
			}
			backlog = nil
			
			pause = false
		}
	}
}

func (executor *commandExecutor[C, R]) executeCommand(ctx context.Context, req Command[C, R]) {
	executor.inflightCmds.Add(1)
	go func() {
		defer executor.inflightCmds.Done()
		result, err := executor.command(ctx, req.Get())
		if err != nil {
			executor.errBuff.Write(err)
			if errors.Is(err, io.EOF) {
				executor.backlogChan <- req
				return
			}

			req.ReturnError(err)
			return
		}

		req.Return(result)
	}()
}

func (executor *commandExecutor[Req, Resp]) PauseExecution() {
	notify := make(chan struct{})
	executor.pauseExecution <- notify
	<-notify
}

func (executor *commandExecutor[Req, Resp]) ResumeExecution() {
	executor.resumeExecution.Send()
}
