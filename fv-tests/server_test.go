// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package fv_tests_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/typha/pkg/snapcache"
	"github.com/projectcalico/typha/pkg/syncserver"
)

var _ = Describe("With an in-process Server", func() {
	var snapCache *snapcache.Cache
	var server *syncserver.Server
	var cxt context.Context
	var cancel context.CancelFunc

	BeforeEach(func() {
		snapCache = snapcache.New(snapcache.Config{
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		server = syncserver.New(snapCache, syncserver.Config{
			DropInterval: 100 * time.Millisecond,
			Port:         syncserver.PortRandom,
		})
		cxt, cancel = context.WithCancel(context.Background())
		snapCache.Start(cxt)
		server.Start(cxt)
	})

	It("should choose a port", func() {
		Expect(server.Port()).ToNot(BeZero())
	})

	AfterEach(func() {
		cancel()
		server.Finished.Wait()
	})
})
