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
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	SOURCE1 = "source1"
	SOURCE2 = "source2"
	SOURCE3 = "source3"
)

var _ = Describe("Health", func() {

	var (
		aggregator *health.HealthAggregator
	)

	notifySource := func(source string) func() {
		return func() {
			switch source {
			case SOURCE1:
				aggregator.Report(source, &health.HealthReport{Ready: true})
			case SOURCE2:
				aggregator.Report(source, &health.HealthReport{Live: true, Ready: true})
			case SOURCE3:
				aggregator.Report(source, &health.HealthReport{Live: true})
			}
		}
	}

	cancelSource := func(source string) func() {
		return func() {
			aggregator.Report(source, &health.HealthReport{Live: false, Ready: false})
		}
	}

	BeforeEach(func() {
		aggregator = health.NewHealthAggregator()
		aggregator.RegisterReporter(SOURCE1, &health.HealthReport{Ready: true}, 1*time.Second)
		aggregator.RegisterReporter(SOURCE2, &health.HealthReport{Live: true, Ready: true}, 1*time.Second)
		aggregator.RegisterReporter(SOURCE3, &health.HealthReport{Live: true}, 1*time.Second)
	})

	It("is initially live but not ready", func() {
		Expect(aggregator.Summary().Ready).To(BeFalse())
		Expect(aggregator.Summary().Live).To(BeTrue())
	})

	Context("with ready reports", func() {

		BeforeEach(func() {
			notifySource(SOURCE1)()
			notifySource(SOURCE2)()
		})

		It("is ready and live", func() {
			Expect(aggregator.Summary().Ready).To(BeTrue())
			Expect(aggregator.Summary().Live).To(BeTrue())
		})

		Context("with live report", func() {

			BeforeEach(notifySource(SOURCE3))

			It("is ready and live", func() {
				Expect(aggregator.Summary().Ready).To(BeTrue())
				Expect(aggregator.Summary().Live).To(BeTrue())
			})
		})

		Context("with not-ready report", func() {

			BeforeEach(cancelSource(SOURCE1))

			It("is live but not ready", func() {
				Expect(aggregator.Summary().Ready).To(BeFalse())
				Expect(aggregator.Summary().Live).To(BeTrue())
			})
		})
	})

	Context("with live reports", func() {

		BeforeEach(func() {
			notifySource(SOURCE3)()
			notifySource(SOURCE2)()
		})

		It("is live but not ready", func() {
			Expect(aggregator.Summary().Live).To(BeTrue())
			Expect(aggregator.Summary().Ready).To(BeFalse())
		})

		Context("with ready report also", func() {

			BeforeEach(notifySource(SOURCE1))

			It("is ready and live", func() {
				Expect(aggregator.Summary().Ready).To(BeTrue())
				Expect(aggregator.Summary().Live).To(BeTrue())
			})

			Context("with time passing so that reports expire", func() {

				BeforeEach(func() {
					time.Sleep(2 * time.Second)
				})

				It("is not ready and not live", func() {
					Expect(aggregator.Summary().Ready).To(BeFalse())
					Expect(aggregator.Summary().Live).To(BeFalse())
				})
			})
		})

		Context("with not-live report", func() {

			BeforeEach(cancelSource(SOURCE3))

			It("is not ready and not live", func() {
				Expect(aggregator.Summary().Ready).To(BeFalse())
				Expect(aggregator.Summary().Live).To(BeFalse())
			})
		})
	})
})

var _ = Describe("Health timeouts", func() {

	var (
		aggregator *health.HealthAggregator
	)

	notifySource := func(source string, detail string) {
		switch source {
		case SOURCE1:
			aggregator.Report(source, &health.HealthReport{Ready: true, Detail: detail})
		case SOURCE2:
			aggregator.Report(source, &health.HealthReport{Live: true, Ready: true, Detail: detail})
		}
	}

	BeforeEach(func() {
		aggregator = health.NewHealthAggregator()
		// One reporter with 100ms timeout.
		aggregator.RegisterReporter(SOURCE1, &health.HealthReport{Ready: true}, 100*time.Millisecond)
		// One reporter with zero timeout, which means its reports do not expire.
		aggregator.RegisterReporter(SOURCE2, &health.HealthReport{Live: true, Ready: true}, 0)
	})

	Context("with ready reports", func() {

		BeforeEach(func() {
			notifySource(SOURCE1, "")
			notifySource(SOURCE2, "but very busy!")
		})

		It("is ready and live", func() {
			Expect(aggregator.Summary().Ready).To(BeTrue())
			Expect(aggregator.Summary().Live).To(BeTrue())
			Expect(aggregator.Summary().Detail).To(Equal(strings.Join([]string{
				"+-----------+---------+----------------+-----------------+----------------+",
				"| COMPONENT | TIMEOUT |    LIVENESS    |    READINESS    |     DETAIL     |",
				"+-----------+---------+----------------+-----------------+----------------+",
				"| source1   | 100ms   | -              | reporting ready |                |",
				"| source2   | 0s      | reporting live | reporting ready | but very busy! |",
				"+-----------+---------+----------------+-----------------+----------------+",
			}, "\n")))
		})

		Context("after waiting past one reporter's timeout", func() {

			BeforeEach(func() { time.Sleep(200 * time.Millisecond) })

			It("is still live but not ready", func() {
				// Because one of the readiness reporters has expired.
				Expect(aggregator.Summary().Ready).To(BeFalse())
				// Because the liveness reporter has no timeout.
				Expect(aggregator.Summary().Live).To(BeTrue())
			})
		})
	})
})
