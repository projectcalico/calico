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

// CommandExecutor executes commands sent using the Send channel asynchronously. The result is sent back on the <-chan Result[R}
// channel when the command has executed. If the command output results in an EOF, the command is backlogged. EOF signals
// that the call must fix something, meaning it needs to pause, fix whatever is wrong, and then resume execution.
// Resuming ensures the backlogged cmds are then executed again.
type CommandExecutor[C any, R any] interface {
	Send(C) <-chan Result[R]
	ExecutionController
}

// ExecutionController is an interface to manage the execution of commands of an Executor. It allows you to stop and resume
// command execution, as well as retrieve a signaler to notify you about shutdown.
type ExecutionController interface {
	DrainAndBacklog() Signaler
	Resume()
	ShutdownSignaler() Signaler
}

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

type commandExecutor[C any, R any] struct {
	command             func(context.Context, C) (R, error)
	drainAndBacklogSig  chan Signaler
	resumeBackloggedSig Signaler
	cmdChan             chan Command[C, R]
	// backlogChan contains all the commands that failed with EOF, waiting to be retried.
	backlogChan chan Command[C, R]
	// inflightCmds keeps track of the number of commands that are currently being executed.
	inflightCmds        sync.WaitGroup
	executeSig          Signaler
	shutdownCompleteSig Signaler
	errBuff             ErrorBuffer

	backLogCommands bool
	backlog         []Command[C, R]
}

func NewCommandCoordinator(executors ...ExecutionController) ExecutionController {
	var coordinator executorCoordinator
	for _, executor := range executors {
		coordinator = append(coordinator, executor)
	}
	return coordinator
}

// NewCommandExecutor creates a new CommandExecutor implementation. It calls the given function f with the command given
// to Send. Any errors from the function are sent over the errBuff. If an EOF is sent over the error buff, the caller
// must pause the executor, restart / fix whatever processes need restarting or fixing, then resume execution (using the
// PauseExecution and ResumeExecution functions). ResumeExecution re runs the commands that failed with EOF.
func NewCommandExecutor[C any, R any](ctx context.Context, errBuff ErrorBuffer, f func(context.Context, C) (R, error)) CommandExecutor[C, R] {
	executor := &commandExecutor[C, R]{
		command:             f,
		errBuff:             errBuff,
		cmdChan:             make(chan Command[C, R], 100),
		backlogChan:         make(chan Command[C, R], 100),
		drainAndBacklogSig:  make(chan Signaler, 100),
		resumeBackloggedSig: NewSignaler(),

		executeSig:          NewSignaler(),
		shutdownCompleteSig: NewSignaler(),
	}

	go executor.loop(ctx)
	return executor
}

func (executor *commandExecutor[C, R]) loop(shutdownCtx context.Context) {
	ctx, stopCommands := context.WithCancel(shutdownCtx)

	// Used to ensure we don't resume execution if we haven't finished draining. This can happen if the caller of DrainAndBacklog
	// doesn't wait on the channel provided.
	defer func() {
		defer stopCommands()
		defer executor.shutdownCompleteSig.Close()

		// close the cmdChan in case anything tries to write to it. This will ensure a panic occurs while trying to
		// clean up any outstanding cmd.
		close(executor.cmdChan)

		// Wait for inflight requests to finish before handling outstanding cmds.
		executor.inflightCmds.Wait()

		close(executor.backlogChan)

		// Add all outstanding commands in the backlog or cmd channels to the backlog slice.
		executor.backlog = append(executor.backlog, ReadAll(executor.backlogChan)...)
		executor.backlog = append(executor.backlog, ReadAll(executor.cmdChan)...)

		logrus.Debug("Returning errors for outstanding requests due to shutdown.")
		for _, cmd := range executor.backlog {
			cmd.ReturnError(context.Canceled)
		}
		logrus.Debug("Finished returning errors for outstanding requests due to shutdown.")

		executor.executeSig.Close()
		close(executor.drainAndBacklogSig)
		executor.resumeBackloggedSig.Close()
	}()

	var draining chan struct{}
	var delayResume chan struct{}
	for {
		select {
		case <-shutdownCtx.Done():
			logrus.Debug("Shutdown signal received, shutting executor down...")
			return
		case cmd := <-executor.cmdChan:
			logrus.Debugf("Received command.")
			if !executor.backLogCommands {
				executor.executeCommand(ctx, cmd)
			} else {
				executor.backlog = append(executor.backlog, cmd)
			}
		case cmd := <-executor.backlogChan:
			executor.backlog = append(executor.backlog, cmd)
		case signal := <-executor.drainAndBacklogSig:
			logrus.Debugf("Received requeue signal.")
			executor.backLogCommands = true
			stopCommands()
			draining = make(chan struct{})
			go func() {
				defer signal.Send()
				defer close(draining)

				logrus.Debugf("Waiting for inflight commands to finish...")
				executor.inflightCmds.Wait()
				executor.errBuff.Clear()
				logrus.Debugf("Inflight commands finished, notifying listeners.")
			}()
		case <-executor.resumeBackloggedSig.Receive():
			logrus.Debugf("Received resume signal.")
			if draining != nil {
				// If the draining channel is not nil and hasn't been closed then we're still draining. We need to
				// delay resuming so the backlog can be written too.
				if _, read := ReadNoWait(draining); !read {
					delayResume = draining
					continue
				}
			}

			// Handle the backlog before resuming execution.
			ctx, stopCommands = executor.execBacklog(shutdownCtx)
		case <-delayResume:
			// Handle the backlog before resuming execution.
			ctx, stopCommands = executor.execBacklog(shutdownCtx)

			// reset the delayResume.
			delayResume = nil
		}
	}
}

func (executor *commandExecutor[C, R]) execBacklog(shutdownCtx context.Context) (context.Context, func()) {
	ctx, stopCommands := context.WithCancel(shutdownCtx)
	for _, cmd := range executor.backlog {
		executor.executeCommand(ctx, cmd)
	}
	executor.backlog = nil
	executor.backLogCommands = false

	// context and cancel function need to be reset.
	return ctx, stopCommands
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
	executor.drainAndBacklogSig <- signal
	return signal
}

// Resume resumes execution of commands sent using Send after DrainAndBacklog is called. Before new commands are executed,
// all backlogged commands are executed. Execution of backlogged commands (or new commands in general) are done in the background,
// so executing the backlog is always a quick operation and won't block new commands from being executed.
func (executor *commandExecutor[Req, Resp]) Resume() {
	executor.resumeBackloggedSig.Send()
}

func (executor *commandExecutor[C, R]) ShutdownSignaler() Signaler {
	return executor.shutdownCompleteSig
}
