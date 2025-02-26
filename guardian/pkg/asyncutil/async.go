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

// AsyncCommandExecutor executes commands sent using the Send channel asynchronously. The result is sent back on the <-chan Result[R}
// channel when the command has executed. If the command output results in an EOF, the command is backlogged. EOF signals
// that the call must fixe something, meaning it needs to pause, fix whatever is wrong, and then resume execution.
// Resuming ensures the backlogged cmds are then executed again.
type AsyncCommandExecutor[C any, R any] interface {
	Send(C) <-chan Result[R]
	ExecutionController
}

// ExecutionController manages multiple CommandExecutors.
type ExecutionController interface {
	DrainAndBacklog() Signaler
	Resume()
	ShutdownSignaler() Signaler
}

// CommandExecutorGroup manages multiple CommandExecutors.
type executorCoordinator []ExecutionController

func (coordinator executorCoordinator) DrainAndBacklog() Signaler {
	var signalers []Signaler
	for _, executor := range coordinator {
		signalers = append(signalers, executor.DrainAndBacklog())
	}

	signal := NewSignaler()
	go func() {
		defer signal.Send()
		for _, signaler := range signalers {
			<-signaler.Receive()
		}
	}()

	return signal
}

func (coordinator executorCoordinator) Resume() {
	for _, executor := range coordinator {
		executor.Resume()
	}
}

func (coordinator executorCoordinator) ShutdownSignaler() Signaler {
	var signalers []Signaler
	for _, executor := range coordinator {
		signalers = append(signalers, executor.ShutdownSignaler())
	}

	signal := NewSignaler()
	go func() {
		defer signal.Send()
		for _, signaler := range signalers {
			<-signaler.Receive()
		}
	}()

	return signal
}

type commandExecutor[Req any, Resp any] struct {
	command          func(context.Context, Req) (Resp, error)
	pauseAndBacklog  chan Signaler
	resumeBacklogged Signaler
	cmdChan          chan Command[Req, Resp]
	// backlogChan contains all the commands that failed with EOF, waiting to be retried.
	backlogChan chan Command[Req, Resp]
	// inflightCmds keeps track of the number of commands that are currently being executed.
	inflightCmds        sync.WaitGroup
	executeSig          Signaler
	shutdownCompleteSig Signaler
	errBuff             AsyncErrorBuffer
}

func NewCommandCoordinator(executors ...ExecutionController) ExecutionController {
	var coordinator executorCoordinator
	for _, executor := range executors {
		coordinator = append(coordinator, executor)
	}
	return coordinator
}

// NewAsyncCommandExecutor creates a new CommandExecutor implementation. It calls the given function f with the command given
// to Send. Any errors from the function are sent over the errBuff. If an EOF is sent over the error buff, the caller
// must pause the executor, restart / fix whatever processes need restarting or fixing, then resume execution (using the
// PauseExecution and ResumeExecution functions). ResumeExecution re runs the commands that failed with EOF.
func NewAsyncCommandExecutor[C any, R any](ctx context.Context, errBuff AsyncErrorBuffer, f func(context.Context, C) (R, error)) AsyncCommandExecutor[C, R] {
	hdlr := &commandExecutor[C, R]{
		command:          f,
		errBuff:          errBuff,
		cmdChan:          make(chan Command[C, R], 100),
		backlogChan:      make(chan Command[C, R], 100),
		pauseAndBacklog:  make(chan Signaler, 100),
		resumeBacklogged: NewSignaler(),

		executeSig:          NewSignaler(),
		shutdownCompleteSig: NewSignaler(),
	}

	go hdlr.loop(ctx)
	return hdlr
}

func (executor *commandExecutor[C, R]) loop(shutdownCtx context.Context) {
	var backlog []Command[C, R]

	defer close(executor.cmdChan)
	defer close(executor.backlogChan)
	defer executor.executeSig.Close()
	defer close(executor.pauseAndBacklog)
	defer executor.resumeBacklogged.Close()

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
		case signal := <-executor.pauseAndBacklog:
			logrus.Debugf("Received requeue signal.")
			pause = true
			stopCommands()
			go func() {
				defer signal.Send()

				executor.inflightCmds.Wait()
				executor.errBuff.Clear()
			}()
		case <-executor.resumeBacklogged.Receive():
			logrus.Debugf("Received resume signal.")
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
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				executor.backlogChan <- req
				return
			}

			req.ReturnError(err)
			return
		}

		req.Return(result)
	}()
}

func (executor *commandExecutor[C, R]) Receive() <-chan Command[C, R] {
	return executor.cmdChan
}

func (executor *commandExecutor[C, R]) Send(params C) <-chan Result[R] {
	cmd, resultChan := NewCommand[C, R](params)
	executor.cmdChan <- cmd
	return resultChan
}

// DrainAndBacklog gracefully stops outstanding commands, possibly allows some commands to finish while stopping others.
// Commands that don't finish successfully (stopped) are added to the backlog. All incoming commands from send are
// added to the backlog as well. When resume is called the commands on the backlog are executed and new commands are
// executed immediately.
func (executor *commandExecutor[Req, Resp]) DrainAndBacklog() Signaler {
	signal := NewSignaler()
	executor.pauseAndBacklog <- signal
	return signal
}

// Resume resumes execution of commands sent using Send after DrainAndBacklog is called. Before new commands are executed,
// all backlogged commands are executed. Execution of backlogged commands (or new commands in general) are done in the background,
// so executing the backlog is always a quick operation and won't block new commands from being executed.
func (executor *commandExecutor[Req, Resp]) Resume() {
	executor.resumeBacklogged.Send()
}

func (executor *commandExecutor[C, R]) ShutdownSignaler() Signaler {
	return executor.shutdownCompleteSig
}
