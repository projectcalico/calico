// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package jitter_test

import (
	. "github.com/projectcalico/felix/go/felix/jitter"

	"github.com/Sirupsen/logrus"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"time"
)

var _ = Describe("20ms + 10ms Ticker", func() {
	var ticker *Ticker
	var startTime time.Time
	BeforeEach(func() {
		startTime = time.Now()
		ticker = NewTicker(20*time.Millisecond,
			10*time.Millisecond)
	})
	AfterEach(func() {
		ticker.Stop()
	})
	It("should never tick before minDelay", func() {
		<-ticker.C
		now := time.Now()
		duration := now.Sub(startTime)
		Expect(duration).To(BeNumerically(">=", 20*time.Millisecond))
	}, 1)
	It("should tick before max delay", func() {
		now := <-ticker.C
		duration := now.Sub(startTime)
		// We give it an extra few ms to allow for a timer variance.
		Expect(duration).To(BeNumerically("<=", 32*time.Millisecond))
	}, 1)
	It("should produce longer and shorter ticks", func() {
		lastTime := startTime
		foundLT5 := false
		foundGT5 := false
		for i := 0; i < 40; i++ {
			<-ticker.C
			now := time.Now()
			duration := time.Now().Sub(lastTime)
			logrus.WithField("duration", duration).Debug("Tick")
			if duration < 25*time.Millisecond {
				foundLT5 = true
			} else {
				foundGT5 = true
			}
			if foundLT5 && foundGT5 {
				break
			}
			lastTime = now
		}
		Expect(foundLT5).To(BeTrue())
		Expect(foundGT5).To(BeTrue())
	}, 1)
})

var _ = Describe("Ticker constructor", func() {
	It("should panic on negative duration", func() {
		Expect(func() { NewTicker(-1*time.Second, 0) }).To(Panic())
	})
	It("should panic on negative jitter", func() {
		Expect(func() { NewTicker(1*time.Second, -1*time.Second) }).To(Panic())
	})
})
