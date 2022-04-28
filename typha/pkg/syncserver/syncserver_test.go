// Copyright (c) 2017,2021 Tigera, Inc. All rights reserved.
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

package syncserver_test

import (
	. "github.com/projectcalico/calico/typha/pkg/syncserver"

	"math"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// These low-level tests complement the FV tests (in typha/fv-tests), which spin up the server on a real port.
var _ = Describe("With zero config", func() {
	var config Config
	BeforeEach(func() {
		config = Config{}
	})
	It("it should apply correct defaults", func() {
		config.ApplyDefaults()
		Expect(config).To(Equal(Config{
			MaxMessageSize:                 100,
			MaxFallBehind:                  300 * time.Second,
			NewClientFallBehindGracePeriod: 300 * time.Second,
			MinBatchingAgeThreshold:        100 * time.Millisecond,
			PingInterval:                   10 * time.Second,
			PongTimeout:                    60 * time.Second,
			DropInterval:                   time.Second,
			MaxConns:                       math.MaxInt32,
			Port:                           5473,
		}))
	})
	It("should convert random port to 0", func() {
		config.Port = PortRandom
		config.ApplyDefaults()
		Expect(config.ListenPort()).To(Equal(0))
	})
	It("should convert 0 port to default", func() {
		config.ApplyDefaults()
		Expect(config.ListenPort()).To(Equal(5473))
	})
})
