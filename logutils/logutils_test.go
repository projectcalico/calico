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

package logutils_test

import (
	. "github.com/projectcalico/felix/logutils"

	"bytes"
	"io"

	log "github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Logutils", func() {
	ourHook := ContextHook{}
	var savedWriter io.Writer
	var buf *bytes.Buffer
	BeforeEach(func() {
		log.AddHook(ourHook)
		savedWriter = log.StandardLogger().Out
		buf = &bytes.Buffer{}
		log.StandardLogger().Out = buf
	})
	AfterEach(func() {
		log.StandardLogger().Out = savedWriter
		levelHooks := log.StandardLogger().Hooks
		for level, hooks := range levelHooks {
			j := 0
			for _, hook := range hooks {
				if hook == ourHook {
					continue
				}
				hooks[j] = hook
				j += 1
			}
			levelHooks[level] = hooks[:len(hooks)-1]
		}
	})

	It("Should add correct file when invoked via log.Info", func() {
		log.Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
	It("Should add correct file when invoked via Logger.Info", func() {
		log.StandardLogger().Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
	It("Should add correct file when invoked via log.WithField(...).Info", func() {
		log.WithField("foo", "bar").Info("Test log")
		Expect(buf.String()).To(ContainSubstring("logutils_test.go"))
	})
})
