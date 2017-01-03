// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package main

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var exitCode int

func fakeExitFunction(ec int) {
	exitCode = ec
}

var _ = Describe("Non-etcd related tests", func() {

	Describe("Logging tests", func() {
		Context("Test message", func() {
			message("Test message %d, %s", 4, "END")
		})
		Context("Test warning", func() {
			warning("Test message %d, %s", 4, "END")
		})
		Context("Test fatal", func() {
			fatal("Test message %d, %s", 4, "END")
		})
	})

	Describe("Termination tests", func() {
		exitCode = 0
		Context("Test termination", func() {
			oldExit := exitFunction
			exitFunction = fakeExitFunction
			defer func() { exitFunction = oldExit }()
			terminate()
			It("should have terminated", func() {
				Expect(exitCode).To(Equal(1))
			})
		})
	})
})
