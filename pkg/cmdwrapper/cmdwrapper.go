// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package cmdwrapper

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// RestartReturnCode is the exit code wrapped processes (currently felix
	// and kube-controllers) use to signal that they are restarting due to a
	// configuration change. WrapSelf re-execs the child on this code.
	RestartReturnCode int = 129

	// signalBufferSize is the size of the signal-forwarding channel.
	// signal.Notify drops signals when the channel is full, so this needs to
	// be large enough to absorb short bursts.
	signalBufferSize = 16

	// restartBackoff is the minimum delay between restarts, to prevent a
	// misconfigured child from busy-looping through RestartReturnCode.
	restartBackoff = 100 * time.Millisecond
)

// WrapSelf provides restart-on-RestartReturnCode semantics for a component
// that runs as a subcommand of the current executable (e.g. "calico
// component felix"). The outer invocation re-execs the current program with
// the same argv, setting innerEnvVar=1 in the child's environment; the
// inner invocation sees innerEnvVar=="1" and runs fn directly.
//
// innerEnvVar must be non-empty and should be unique to this binary and
// component (for example "CALICO_FELIX_INNER"). Any pre-existing value of
// innerEnvVar in the outer's environment is stripped before re-execing, so
// a stale or user-supplied value cannot confuse the child.
//
// If fn returns normally, the inner exits 0 and the outer follows suit. If
// fn calls os.Exit(N) or panics, the inner exits with that code and the
// outer propagates it. The caller is responsible for configuring logrus
// before calling WrapSelf.
func WrapSelf(innerEnvVar string, fn func()) {
	if innerEnvVar == "" {
		panic("cmdwrapper.WrapSelf: innerEnvVar must not be empty")
	}
	if os.Getenv(innerEnvVar) == "1" {
		fn()
		return
	}
	env := append(stripEnvVar(os.Environ(), innerEnvVar), innerEnvVar+"=1")
	runLoop(os.Args[0], os.Args[1:], env)
}

// stripEnvVar returns environ with any "<key>=..." entries removed. It does
// not modify the input slice.
func stripEnvVar(environ []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(environ))
	for _, e := range environ {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// runLoop starts prog with args and env and restarts it on
// RestartReturnCode, forwarding signals to the child. runLoop never
// returns; it calls os.Exit with the child's last exit code.
func runLoop(prog string, args []string, env []string) {
	sigCh := make(chan os.Signal, signalBufferSize)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)

	for {
		logrus.Infof("Starting %s %v", prog, args)
		cmd := exec.Command(prog, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = env
		setPdeathsig(cmd)

		if err := cmd.Start(); err != nil {
			logrus.WithError(err).Fatalf("Failed to start %s", prog)
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go forwardSignals(cmd.Process, sigCh, stop, &wg)

		cmdWaitErr := cmd.Wait()
		close(stop)
		wg.Wait()

		exitCode := classifyExit(cmdWaitErr, prog)
		if exitCode == RestartReturnCode {
			logrus.Infof("Received exit status %d, restarting %s", exitCode, prog)
			time.Sleep(restartBackoff)
			continue
		}
		logrus.Infof("Received exit status %d for %s", exitCode, prog)
		os.Exit(exitCode)
	}
}

func forwardSignals(p *os.Process, sigCh <-chan os.Signal, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case s := <-sigCh:
			// SIGCHLD (Linux) arrives because our child exited; cmd.Wait
			// handles reaping, so we don't need to forward it.
			if shouldIgnoreSignal(s) {
				continue
			}
			if err := p.Signal(s); err != nil {
				// The child may have already exited (common during
				// teardown), so this is not fatal.
				logrus.WithError(err).WithField("signal", s).Debug("Failed to forward signal to wrapped process")
			}
		case <-stop:
			return
		}
	}
}

// classifyExit maps cmd.Wait()'s error to a numeric exit code to propagate.
// Non-ExitError failures (e.g. I/O errors reaping the child) are logged and
// reported as exit code 1.
func classifyExit(cmdWaitErr error, prog string) int {
	if cmdWaitErr == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(cmdWaitErr, &ee) {
		return ee.ExitCode()
	}
	logrus.WithError(cmdWaitErr).Errorf("Failed to wait for %s to finish", prog)
	return 1
}
