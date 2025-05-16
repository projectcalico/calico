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

	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/lib/std/log"
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
	DrainAndBacklog() <-chan struct{}
	Resume()
	WaitForShutdown() <-chan struct{}
}

type executorCoordinator []ExecutionController

func (coordinator executorCoordinator) DrainAndBacklog() <-chan struct{} {
	signal := make(chan struct{})
	go func() {
		defer close(signal)
		for _, executor := range coordinator {
			<-executor.DrainAndBacklog()
		}
	}()

	return signal
}

func (coordinator executorCoordinator) Resume() {
	for _, executor := range coordinator {
		executor.Resume()
	}
}

func (coordinator executorCoordinator) WaitForShutdown() <-chan struct{} {
	signal := make(chan struct{})
	go func() {
		defer close(signal)
		for _, executor := range coordinator {
			<-executor.WaitForShutdown()
		}
	}()

	return signal
}

type commandExecutor[C any, R any] struct {
	command func(context.Context, C) (R, error)
	cmdChan chan Command[C, R]
	// backlogChan contains all the commands that failed with EOF, waiting to be retried.
	backlogChan chan Command[C, R]
	// inflightCmds keeps track of the number of commands that are currently being executed.
	inflightCmds sync.WaitGroup

	resumeBackloggedSig chan struct{}
	drainAndBacklogSig  chan chan struct{}
	shutdownCompleteSig chan struct{}

	errBuff ErrorBuffer

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
		drainAndBacklogSig:  make(chan chan struct{}, 100),
		resumeBackloggedSig: make(chan struct{}),
		shutdownCompleteSig: make(chan struct{}),
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
		defer close(executor.shutdownCompleteSig)

		// close the cmdChan in case anything tries to write to it. This will ensure a panic occurs while trying to
		// clean up any outstanding cmd.
		close(executor.cmdChan)

		// Wait for inflight requests to finish before handling outstanding cmds.
		executor.inflightCmds.Wait()

		close(executor.backlogChan)

		// Add all outstanding commands in the backlog or cmd channels to the backlog slice.
		executor.drainBacklogChannel()
		executor.backlog = append(executor.backlog, chanutil.ReadAllNonBlocking(executor.cmdChan)...)

		if len(executor.backlog) > 0 {
			log.Debug("Returning errors for outstanding commands due to shutdown...")
			for _, cmd := range executor.backlog {
				cmd.ReturnError(context.Canceled)
			}
			log.Debug("Finished returning errors for outstanding commands.")
		} else {
			log.Debug("No outstanding commands, shutting down..")
		}

		close(executor.drainAndBacklogSig)
		close(executor.resumeBackloggedSig)
	}()

	var draining chan struct{}
	var delayResume chan struct{}
	for {
		select {
		case <-shutdownCtx.Done():
			log.Debug("Shutdown signal received, shutting executor down...")
			return
		case cmd := <-executor.cmdChan:
			log.Debugf("Received command.")
			if !executor.backLogCommands {
				log.Debugf("Executing command immediately..")
				executor.executeCommand(ctx, cmd)
			} else {
				log.Debugf("Backlog commands set, adding command to backlog (current backlog size: %d).", len(executor.backlog))
				executor.backlog = append(executor.backlog, cmd)
			}
		case cmd := <-executor.backlogChan:
			log.Debugf("Received backlog command (current backlog size: %d).", len(executor.backlog))
			if len(executor.backlog) > 50 {
				log.Warn("Backlog size exceeded has exceed 50.")
			}
			executor.backlog = append(executor.backlog, cmd)
		case signal := <-executor.drainAndBacklogSig:
			log.Debugf("Received requeue signal.")
			executor.backLogCommands = true
			stopCommands()
			draining = make(chan struct{})
			go func() {
				defer close(signal)
				defer close(draining)

				log.Debug("Waiting for inflight commands to finish...")
				executor.inflightCmds.Wait()
				// Clear the error buffer, as we don't want to return any errors when we resume accepting commands.
				executor.errBuff.Clear()
				log.Debug("Inflight commands finished, notifying listeners.")
			}()
		case <-executor.resumeBackloggedSig:
			log.Debugf("Received resume signal.")
			if draining != nil {
				log.Debug("Waiting for drain to finish...")
				// If the draining channel is not nil and hasn't been closed then we're still draining. We need to
				// delay resuming so the backlog can be written too.
				if _, read := chanutil.ReadNonBlocking(draining); !read {
					log.Debug("delay resume signal not set, setting it.")
					delayResume = draining
					continue
				}
				log.Debug("delay resume signal already set.")
			}

			// Handle the backlog before resuming execution.
			ctx, stopCommands = executor.execBacklog(shutdownCtx)
		case <-delayResume:
			log.Debug("Delay resume signal received, handling backlog.")

			// Handle the backlog before resuming execution.
			ctx, stopCommands = executor.execBacklog(shutdownCtx)

			// reset the delayResume.
			delayResume = nil
		}
	}
}

func (executor *commandExecutor[C, R]) drainBacklogChannel() {
	log.Debugf("Backlog size: %d, adding to backlog.", len(executor.backlog))
	executor.backlog = append(executor.backlog, chanutil.ReadAllNonBlocking(executor.backlogChan)...)
}

func (executor *commandExecutor[C, R]) execBacklog(shutdownCtx context.Context) (context.Context, func()) {
	// Just in case there's anything left on the backlog channel ensure it's drained off and added to the backlog slice.
	if len(executor.backlog) > 0 {
		executor.drainBacklogChannel()
	}

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
			log.WithError(err).Debug("Error executing command")
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
func (executor *commandExecutor[Req, Resp]) DrainAndBacklog() <-chan struct{} {
	signal := make(chan struct{})
	executor.drainAndBacklogSig <- signal
	return signal
}

// Resume resumes execution of commands sent using Send after DrainAndBacklog is called. Before new commands are executed,
// all backlogged commands are executed. Execution of backlogged commands (or new commands in general) are done in the background,
// so executing the backlog is always a quick operation and won't block new commands from being executed.
func (executor *commandExecutor[Req, Resp]) Resume() {
	executor.resumeBackloggedSig <- struct{}{}
}

func (executor *commandExecutor[C, R]) WaitForShutdown() <-chan struct{} {
	return executor.shutdownCompleteSig
}
