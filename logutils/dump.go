// +build !windows

// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package logutils

import (
	"os"
	"os/signal"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/config"
)

func DumpHeapMemoryProfile(configParams *config.Config) {
	// If a memory profile file name is configured, dump a heap memory profile.  If the
	// configured filename includes "<timestamp>", that will be replaced with a stamp indicating
	// the current time.
	memProfFileName := configParams.DebugMemoryProfilePath
	if memProfFileName != "" {
		logCxt := log.WithField("file", memProfFileName)
		logCxt.Info("Asked to create a memory profile.")

		// If the configured file name includes "<timestamp>", replace that with the current
		// time.
		if strings.Contains(memProfFileName, "<timestamp>") {
			timestamp := time.Now().Format("2006-01-02-15:04:05")
			memProfFileName = strings.Replace(memProfFileName, "<timestamp>", timestamp, 1)
			logCxt = log.WithField("file", memProfFileName)
		}

		// Open a file with that name.
		memProfFile, err := os.Create(memProfFileName)
		if err != nil {
			logCxt.WithError(err).Fatal("Could not create memory profile file")
			memProfFile = nil
		} else {
			defer memProfFile.Close()
			logCxt.Info("Writing memory profile...")
			// The initial resync uses a lot of scratch space so now is
			// a good time to force a GC and return any RAM that we can.
			debug.FreeOSMemory()
			if err := pprof.WriteHeapProfile(memProfFile); err != nil {
				logCxt.WithError(err).Fatal("Could not write memory profile")
			}
			logCxt.Info("Finished writing memory profile")
		}
	}
}

func DumpHeapMemoryOnSignal(configParams *config.Config) {
	// On receipt of SIGUSR1, write out heap profile.
	usr1SignalChan := make(chan os.Signal, 1)
	signal.Notify(usr1SignalChan, syscall.SIGUSR1)
	go func() {
		for {
			<-usr1SignalChan
			DumpHeapMemoryProfile(configParams)
		}
	}()
}
