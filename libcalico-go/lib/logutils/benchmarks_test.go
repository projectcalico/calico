// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"runtime"
	"testing"

	"github.com/sirupsen/logrus"
)

var result bool

func BenchmarkShouldSkipFrame(b *testing.B) {
	var r bool
	for n := 0; n < b.N; n++ {
		r = shouldSkipFrame(runtime.Frame{File: "/home/ubuntu/go/src/github.com/projectcalico/libcalico-go/lib/foo/bar.go"})
	}
	result = r
}

// These functions are here to make sure we have plenty of stack frames to load when we call runtime.Callers()

func benchmarkCallers5(b *testing.B) {
	benchmarkCallers4(b)
}

func benchmarkCallers4(b *testing.B) {
	benchmarkCallers3(b)
}

func benchmarkCallers3(b *testing.B) {
	benchmarkCallers2(b)
}

func benchmarkCallers2(b *testing.B) {
	benchmarkCallers1(b)
}

func benchmarkCallers1(b *testing.B) {
	benchmarkCallers(b)
}

var pcsResult []uintptr
var skipResult int
var entry *logrus.Entry
var globalErr error

func benchmarkCallers(b *testing.B) {
	hook := &ContextHook{}
	e := logrus.WithField("foo", "bar")
	var err error

	for n := 0; n < b.N; n++ {
		err = hook.Fire(e)
	}

	entry = e
	globalErr = err
}

func BenchmarkCallersSkip1(b *testing.B) {
	benchmarkCallers5(b)
}
