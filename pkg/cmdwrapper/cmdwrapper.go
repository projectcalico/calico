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

package cmdwrapper

import (
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/logutils"
)

const (
	RestartReturnCode int = 129
)

// This is a wrapper program to restart the passed in program anytime it exits
// with a status code of 129, which should be used by typha or kube-controllers
// to signal they are restarting due to a configuration change.
func Run() {
	// Set up logging.
	logutils.ConfigureEarlyLogging()
	logutils.ConfigureLogging(&config.Config{
		LogSeverityScreen:       "info",
		DebugDisableLogDropping: true,
	})
	if len(os.Args) < 2 {
		logrus.Fatalf("Invalid invocation of command wrapper, expected: %s <wrapped command>", os.Args[0])
	}
	prog := os.Args[1]
	args := os.Args[2:]

	c := make(chan os.Signal, 1)
	// Capture all signals and send them to our channel which are then passed on to the
	// wrapped command
	signal.Notify(c)

	for {
		logrus.Infof("Starting %s", prog)
		cmd := exec.Command(prog, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Start()
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to start %s", prog)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		stop := make(chan interface{})
		go func() {
			defer wg.Done()
			for {
				select {
				case s := <-c:
					// We don't need to know about SIGCHLD signals since cmd.Wait will give us
					// all we need to know about the command we spawn
					if s == syscall.SIGCHLD {
						continue
					}
					err = cmd.Process.Signal(s)
					if err != nil {
						logrus.WithError(err).Error("Failed so send signal to wrapped command process")
					}
				case <-stop:
					return
				}
			}
		}()
		cmdWaitErr := cmd.Wait()
		close(stop)
		wg.Wait()
		if cmdWaitErr != nil {
			if ee, ok := cmdWaitErr.(*exec.ExitError); ok {
				// If the exitcode is the expected restart code then start our loop over
				// again to re-run the command we're wrapping.
				if ee.ExitCode() == RestartReturnCode {
					logrus.Infof("Received exit status %d, restarting %s", ee.ExitCode(), prog)
					continue
				}
				logrus.Infof("Received exit status %d", ee.ExitCode())
				// Exit with the same exit status of the wrapped command so the code is returned
				// to whatever is running us.
				os.Exit(ee.ExitCode())
			}
			logrus.WithError(cmdWaitErr).Errorf("Failed to wait for %s to finish", prog)
		}

		// If the wrapped command exited successfully then we should do the same.
		os.Exit(0)
	}
}
