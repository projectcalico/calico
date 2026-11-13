// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"os"
	"runtime"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("manageShutdown", func() {
	var exitCodes chan int

	BeforeEach(func() {
		// Both stubs end the calling goroutine, as a real exit would end
		// the process, so nothing after the exit call runs.
		exitCodes = make(chan int, 1)
		recordExit := func(rc int) {
			exitCodes <- rc
			runtime.Goexit()
		}

		oldExit := osExit
		osExit = recordExit
		DeferCleanup(func() { osExit = oldExit })

		// Fatal logs exit through logrus rather than through osExit.
		logger := log.StandardLogger()
		oldLogExit := logger.ExitFunc
		logger.ExitFunc = recordExit
		DeferCleanup(func() { logger.ExitFunc = oldLogExit })
	})

	DescribeTable("exits zero when asked to stop",
		func(sig os.Signal) {
			signalChan := make(chan os.Signal, 1)
			signalChan <- sig
			go manageShutdown(signalChan, make(chan string), nil, nil)

			Eventually(exitCodes, "5s").Should(Receive(Equal(0)))
		},
		Entry("by SIGTERM", syscall.SIGTERM),
		Entry("by SIGINT", syscall.SIGINT),
	)

	It("exits non-zero on a fatal error", func() {
		failureReportChan := make(chan string, 1)
		failureReportChan <- reasonFatalError
		go manageShutdown(make(chan os.Signal), failureReportChan, nil, nil)

		Eventually(exitCodes, "10s").Should(Receive(Not(Equal(0))))
	})

	It("exits with the config-change code on SIGHUP", func() {
		signalChan := make(chan os.Signal, 1)
		signalChan <- syscall.SIGHUP
		go manageShutdown(signalChan, make(chan string), nil, nil)

		Eventually(exitCodes, "10s").Should(Receive(Equal(configChangedRC)))
	})
})

var _ = Describe("shutDownProcess", func() {
	// shutDownProcess never returns: it reports the reason to the shutdown
	// monitor and then panics as a backstop.  Run it in a goroutine and
	// recover so a stray panic can't outlive the spec.
	runInBackground := func(fc *DataplaneConnector, reason string) <-chan any {
		panicked := make(chan any, 1)
		go func() {
			defer func() { panicked <- recover() }()
			fc.shutDownProcess(reason)
		}()
		return panicked
	}

	// Regression test for the start-of-day deadlock: if the shutdown monitor
	// (the only reader of failureReportChan) hasn't started, the report send
	// must not block forever.  Before the fix, the panic backstop sat after
	// an unconditional blocking send, so this hung indefinitely.
	It("panics instead of blocking when the shutdown monitor never reads", func() {
		fc := &DataplaneConnector{
			failureReportChan:     make(chan string), // Unbuffered, no reader.
			shutdownReportTimeout: 100 * time.Millisecond,
		}

		panicked := runInBackground(fc, reasonConfigChanged)
		Eventually(panicked, "5s").Should(Receive(Not(BeNil())))
	})

	It("delivers the reason to the monitor and then panics as a backstop", func() {
		reportChan := make(chan string)
		fc := &DataplaneConnector{
			failureReportChan:     reportChan,
			shutdownReportTimeout: 100 * time.Millisecond,
		}

		received := make(chan string, 1)
		go func() { received <- <-reportChan }()

		panicked := runInBackground(fc, reasonConfigChanged)

		// The reason reaches the monitor: the send is not lost.
		Eventually(received, "5s").Should(Receive(Equal(reasonConfigChanged)))
		// The backstop still fires once the monitor fails to tear us down.
		Eventually(panicked, "5s").Should(Receive(Not(BeNil())))
	})
})
