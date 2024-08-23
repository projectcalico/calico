// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package routetable_test

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/procfs"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	mocknetlink "github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	. "github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/routetable/ownershippol"
)

// Note: these benchmarks must be run as root, because they create a dummy
// interface.

func BenchmarkResync1024(b *testing.B) {
	benchResyncNumRoutes(b, 1024)
}
func BenchmarkResync4096(b *testing.B) {
	benchResyncNumRoutes(b, 4096)
}
func BenchmarkResync65536(b *testing.B) {
	benchResyncNumRoutes(b, 65536)
}

func benchResyncNumRoutes(b *testing.B, numRoutes int) {
	RegisterTestingT(b)

	if os.Getuid() != 0 {
		b.Fatal("This test must be run as root.")
	}

	logutils.ConfigureEarlyLogging()
	logrus.SetLevel(logrus.WarnLevel)

	ifaceName := fmt.Sprintf("testcali%04x", rand.Intn(65536))
	utils.Run("ip", "link", "add", "name", ifaceName, "type", "dummy")
	b.Cleanup(func() {
		utils.Run("ip", "link", "del", "dev", ifaceName)
	})
	utils.Run("ip", "link", "set", "dev", ifaceName, "up")

	sum := logutils.NewSummarizer("test")
	mockDP := mocknetlink.New()
	rt := New(
		ownershippol.NewMainTable(
			dataplanedefs.VXLANIfaceNameV4,
			88,
			[]string{"testcali"},
			false,
		),
		4,
		5*time.Second,
		nil,
		88,
		false,
		unix.RT_TABLE_MAIN,
		sum,
		mockDP,
	)

	n := 0
outer:
	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			rt.RouteUpdate(RouteClassLocalWorkload, ifaceName, Target{
				CIDR: ip.MustParseCIDROrIP(fmt.Sprintf("10.0.%d.%d/32", i, j)),
			})
			n++
			if n == numRoutes {
				break outer
			}
		}
	}
	if n < numRoutes {
		b.Fatalf("Only added %d routes", n)
	}
	err := rt.Apply()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	proc, _ := procfs.NewProc(os.Getpid())
	stat, _ := proc.Stat()
	startCPU := stat.CPUTime()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rt.QueueResync()
		err := rt.Apply()
		if err != nil {
			b.Fatal(err)
		}
	}

	runtime.GC()
	stat, _ = proc.Stat()
	endCPU := stat.CPUTime()
	b.ReportMetric((endCPU-startCPU)/float64(b.N)*1000000000, "ncpu/op")
}
