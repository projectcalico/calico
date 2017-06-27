// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package health_test

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type healthSource string

var (
	SOURCE1 = healthSource("source1")
	SOURCE2 = healthSource("source2")
	SOURCE3 = healthSource("source3")
)

var _ = Describe("Health", func() {

	var (
		healthChannel chan health.HealthIndicator
		state         *health.HealthState
	)

	notifySource := func(source healthSource) func() {
		return func() {
			healthChannel <- health.HealthIndicator{source, 1 * time.Second}
		}
	}

	cancelSource := func(source healthSource) func() {
		return func() {
			healthChannel <- health.HealthIndicator{source, 0}
		}
	}

	BeforeEach(func() {
		healthChannel = make(chan health.HealthIndicator)
		// Note: use a new HealthState, in each test.  Otherwise what can happen is that the
		// closing goroutine from the previous test changes it and confuses the test that is
		// running now...
		state = health.NewHealthState()

		go health.MonitorHealth(
			state,
			set.From(SOURCE1, SOURCE2),
			set.From(SOURCE2, SOURCE3),
			healthChannel,
		)
	})

	AfterEach(func() {
		close(healthChannel)
		Eventually(state.Ready).Should(BeFalse())
		Eventually(state.Live).Should(BeFalse())
	})

	It("initially reports live but not ready", func() {
		Expect(state.Ready()).To(BeFalse())
		Expect(state.Live()).To(BeTrue())
	})

	Context("with indicators for readiness sources", func() {

		BeforeEach(func() {
			notifySource(SOURCE1)()
			notifySource(SOURCE2)()
		})

		It("is ready but not live", func() {
			Eventually(state.Ready).Should(BeTrue())
			Expect(state.Live()).To(BeFalse())
		})

		Context("with liveness source also", func() {

			BeforeEach(notifySource(SOURCE3))

			It("is ready and live", func() {
				Eventually(state.Ready).Should(BeTrue())
				Eventually(state.Live).Should(BeTrue())
			})
		})

		Context("with a source cancelled", func() {

			BeforeEach(cancelSource(SOURCE1))

			It("is not ready and not live", func() {
				Eventually(state.Ready).Should(BeFalse())
				Eventually(state.Live).Should(BeFalse())
			})
		})
	})

	Context("with indicators for liveness sources", func() {

		BeforeEach(func() {
			notifySource(SOURCE3)()
			notifySource(SOURCE2)()
		})

		It("is live but not ready", func() {
			Eventually(state.Live).Should(BeTrue())
			Expect(state.Ready()).To(BeFalse())
		})

		Context("with readiness source also", func() {

			BeforeEach(notifySource(SOURCE1))

			It("is ready and live", func() {
				Eventually(state.Ready).Should(BeTrue())
				Eventually(state.Live).Should(BeTrue())
			})

			Context("with time passing so that indicators expire", func() {

				BeforeEach(func() {
					time.Sleep(2 * time.Second)
				})

				It("is not ready and not live", func() {
					Eventually(state.Ready).Should(BeFalse())
					Eventually(state.Live).Should(BeFalse())
				})
			})
		})

		Context("with a source cancelled", func() {

			BeforeEach(cancelSource(SOURCE3))

			It("is not ready and not live", func() {
				Eventually(state.Ready).Should(BeFalse())
				Eventually(state.Live).Should(BeFalse())
			})
		})
	})
})
