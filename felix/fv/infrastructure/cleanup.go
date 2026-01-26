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

package infrastructure

import (
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils/stacktrace"
)

// cleanupStack is a reusable reverse-order cleanup registry.
// It is thread-safe and does not suppress panics from registered functions.
type cleanupStack struct {
	mu  sync.Mutex
	fns []annotatedFunc
}

type annotatedFunc struct {
	caller string
	f      func()
}

func (c *cleanupStack) Add(f func()) {
	if f == nil {
		return
	}
	c.mu.Lock()
	c.fns = append(c.fns, annotatedFunc{
		f:      f,
		caller: miniStackStrace(),
	})
	c.mu.Unlock()
}

func miniStackStrace() string {
	return stacktrace.MiniStackStrace("/infrastructure/cleanup.go")
}

// Run executes registered functions in reverse order and clears the stack.
// Panics from cleanup functions are allowed to propagate to the caller.
func (c *cleanupStack) Run() {
	logrus.Info("Running cleanup stack...")
	c.mu.Lock()
	fns := c.fns
	c.fns = nil
	c.mu.Unlock()

	runCleanupStack(fns)
}

func runCleanupStack(fs []annotatedFunc) {
	if len(fs) == 0 {
		return
	}

	// We want all cleanup functions to run in reverse order, even if there's
	// a panic.  We also want the panic to propagate so that it causes the test
	// to fail.  By deferring the first function and then recursing, we get
	// both of those properties.
	defer func() {
		logCtx := logrus.WithField("registeredAt", fs[0].caller)
		logCtx.Info("Running cleanup func.")
		// We don't want to recover a panic from runCleanupStack so we call the
		// func via callFuncLogPanic; this limits the scope of recover call.
		callFuncLogPanic(logCtx, fs[0].f)
		logCtx.Info("Cleanup func succeeded.")
	}()
	runCleanupStack(fs[1:])
}

func callFuncLogPanic(logCtx *logrus.Entry, theFunc func()) {
	defer func() {
		if x := recover(); x != nil {
			logCtx.WithField("panic", x).Warn("Cleanup func panicked.")
			panic(x)
		}
	}()

	theFunc()
}
