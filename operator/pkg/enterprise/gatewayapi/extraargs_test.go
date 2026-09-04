// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package gatewayapi

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ensureExtraArg", func() {
	const logPath = "/access_logs/envoy.log"

	It("appends flag and value when the flag is absent", func() {
		Expect(ensureExtraArg(nil, "--log-path", logPath)).
			To(Equal([]string{"--log-path", logPath}))
	})

	It("overrides a value carried over from a custom base EnvoyProxy", func() {
		Expect(ensureExtraArg([]string{"--log-path", "/custom/envoy.log"}, "--log-path", logPath)).
			To(Equal([]string{"--log-path", logPath}))
	})

	It("preserves other args while overriding the flag", func() {
		Expect(ensureExtraArg([]string{"--foo", "bar", "--log-path", "/custom.log"}, "--log-path", logPath)).
			To(Equal([]string{"--foo", "bar", "--log-path", logPath}))
	})

	It("is idempotent across reconciles", func() {
		once := ensureExtraArg([]string{"--log-path", "/custom.log"}, "--log-path", logPath)
		Expect(ensureExtraArg(once, "--log-path", logPath)).To(Equal(once))
	})

	It("does not mutate the input slice (cache safety)", func() {
		in := []string{"--log-path", "/custom.log"}
		_ = ensureExtraArg(in, "--log-path", logPath)
		Expect(in).To(Equal([]string{"--log-path", "/custom.log"}))
	})

	It("leaves a flag-looking token after a bare -- untouched", func() {
		Expect(ensureExtraArg([]string{"--", "--log-path", "/positional"}, "--log-path", logPath)).
			To(Equal([]string{"--log-path", logPath, "--", "--log-path", "/positional"}))
	})

	It("inserts the option before a bare -- separator", func() {
		Expect(ensureExtraArg([]string{"--foo", "bar", "--", "x"}, "--log-path", logPath)).
			To(Equal([]string{"--foo", "bar", "--log-path", logPath, "--", "x"}))
	})
})
