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
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/typha/pkg/health"
	"github.com/projectcalico/typha/pkg/set"
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
		outputs       []bool
		mutex         *sync.Mutex
	)

	getReady := func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return outputs[0]
	}

	getLive := func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return outputs[1]
	}

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
		// Note: use a different pair of locations, in each test, for the calculated "ready"
		// and "live" values.  Otherwise what can happen is that the closing goroutine from
		// the previous test sets them to false and confuses the test that is running now...
		outputs = make([]bool, 2, 2)
		mutex = &sync.Mutex{}

		go health.MonitorHealth(
			&outputs[0], &outputs[1], mutex,
			set.From(SOURCE1, SOURCE2),
			set.From(SOURCE2, SOURCE3),
			healthChannel,
		)
	})

	AfterEach(func() {
		close(healthChannel)
		Eventually(getReady).Should(BeFalse())
		Eventually(getLive).Should(BeFalse())
	})

	It("initially reports false", func() {
		Expect(getReady()).To(BeFalse())
		Expect(getLive()).To(BeFalse())
	})

	Context("with indicators for readiness sources", func() {

		BeforeEach(func() {
			notifySource(SOURCE1)()
			notifySource(SOURCE2)()
		})

		It("is ready but not live", func() {
			Eventually(getReady).Should(BeTrue())
			Expect(getLive()).To(BeFalse())
		})

		Context("with liveness source also", func() {

			BeforeEach(notifySource(SOURCE3))

			It("is ready and live", func() {
				Eventually(getReady).Should(BeTrue())
				Eventually(getLive).Should(BeTrue())
			})
		})

		Context("with a source cancelled", func() {

			BeforeEach(cancelSource(SOURCE1))

			It("is not ready and not live", func() {
				Eventually(getReady).Should(BeFalse())
				Eventually(getLive).Should(BeFalse())
			})
		})
	})

	Context("with indicators for liveness sources", func() {

		BeforeEach(func() {
			notifySource(SOURCE3)()
			notifySource(SOURCE2)()
		})

		It("is live but not ready", func() {
			Eventually(getLive).Should(BeTrue())
			Expect(getReady()).To(BeFalse())
		})

		Context("with readiness source also", func() {

			BeforeEach(notifySource(SOURCE1))

			It("is ready and live", func() {
				Eventually(getReady).Should(BeTrue())
				Eventually(getLive).Should(BeTrue())
			})

			Context("with time passing so that indicators expire", func() {

				BeforeEach(func() {
					time.Sleep(2 * time.Second)
				})

				It("is not ready and not live", func() {
					Eventually(getReady).Should(BeFalse())
					Eventually(getLive).Should(BeFalse())
				})
			})
		})

		Context("with a source cancelled", func() {

			BeforeEach(cancelSource(SOURCE3))

			It("is not ready and not live", func() {
				Eventually(getReady).Should(BeFalse())
				Eventually(getLive).Should(BeFalse())
			})
		})
	})
})
