//go:build !windows

// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.
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
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/config"
)

func DumpHeapMemoryProfile(fileName string) {
	logCxt := log.WithField("file", fileName)
	logCxt.Info("Asked to create a memory profile.")

	fileName = renderFileName(fileName)

	// Open a file with that name.
	f, err := os.Create(fileName)
	if err != nil {
		logCxt.WithError(err).Error("Could not create memory profile file")
		return
	}
	defer f.Close()
	logCxt.Info("Writing memory profile...")
	if err := pprof.WriteHeapProfile(f); err != nil {
		logCxt.WithError(err).Error("Could not write memory profile")
	}
	logCxt.Info("Finished writing memory profile")
}

func DumpCPUProfile(fileName string) {
	logCxt := log.WithField("file", fileName)
	logCxt.Info("Asked to create a CPU profile.")
	fileName = renderFileName(fileName)

	// Open a file with that name.
	f, err := os.Create(fileName)
	if err != nil {
		logCxt.WithError(err).Error("Could not create CPU profile file")
		return
	}
	defer f.Close()

	logCxt.Info("Writing CPU profile...")
	err = pprof.StartCPUProfile(f)
	if err != nil {
		logCxt.WithError(err).Error("Could not start CPU profile")
		return
	}
	defer pprof.StopCPUProfile()
	time.Sleep(10 * time.Second)
	logCxt.Info("Finished writing CPU profile")
}

func renderFileName(template string) string {
	// If the configured file name includes "<timestamp>", replace that with the current
	// time.
	if strings.Contains(template, "<timestamp>") {
		timestamp := time.Now().Format("2006-01-02-15:04:05")
		return strings.Replace(template, "<timestamp>", timestamp, 1)
	}

	return template
}

func RegisterProfilingSignalHandlers(configParams *config.Config) {
	if configParams.DebugMemoryProfilePath != "" {
		// On receipt of SIGUSR1, write out heap profile.
		usr1SignalChan := make(chan os.Signal, 1)
		signal.Notify(usr1SignalChan, syscall.SIGUSR1)
		go func() {
			for {
				<-usr1SignalChan
				DumpHeapMemoryProfile(configParams.DebugMemoryProfilePath)
			}
		}()
	}

	if configParams.DebugCPUProfilePath != "" {
		// On receipt of SIGUSR2, write out CPU profile.
		usr2SignalChan := make(chan os.Signal, 10)
		signal.Notify(usr2SignalChan, syscall.SIGUSR2)
		go func() {
			for {
				<-usr2SignalChan
				DumpCPUProfile(configParams.DebugCPUProfilePath)
			}
		}()
	}
}
