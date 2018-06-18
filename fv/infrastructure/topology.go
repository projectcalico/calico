// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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

package infrastructure

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"regexp"

	"github.com/projectcalico/felix/fv/containers"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

type TopologyOptions struct {
	FelixLogSeverity  string
	EnableIPv6        bool
	ExtraEnvVars      map[string]string
	ExtraVolumes      map[string]string
	WithTypha         bool
	WithFelixTyphaTLS bool
	TyphaLogSeverity  string
	IPIPEnabled       bool
}

func DefaultTopologyOptions() TopologyOptions {
	return TopologyOptions{
		FelixLogSeverity:  "info",
		EnableIPv6:        true,
		ExtraEnvVars:      map[string]string{},
		ExtraVolumes:      map[string]string{},
		WithTypha:         false,
		WithFelixTyphaTLS: false,
		TyphaLogSeverity:  "info",
		IPIPEnabled:       true,
	}
}

// StartSingleNodeEtcdTopology starts an etcd container and a single Felix container; it initialises
// the datastore and installs a Node resource for the Felix node.
func StartSingleNodeEtcdTopology(options TopologyOptions) (felix *Felix, etcd *containers.Container, calicoClient client.Interface) {
	felixes, etcd, calicoClient := StartNNodeEtcdTopology(1, options)
	felix = felixes[0]
	return
}

// StartNNodeEtcdTopology starts an etcd container and a set of Felix hosts.  If n > 1, sets
// up IPIP, otherwise this is skipped.
//
// - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//   but (for simplicity) we don't actually use IPAM to assign IPs.
// - Configures routes between the hosts, giving each host 10.65.x.0/24, where x is the
//   index in the returned array.  When creating workloads, use IPs from the relevant block.
// - Configures the Tunnel IP for each host as 10.65.x.1.
func StartNNodeEtcdTopology(n int, opts TopologyOptions) (felixes []*Felix, etcd *containers.Container, client client.Interface) {
	log.Infof("Starting a %d-node etcd topology.", n)

	eds, err := GetEtcdDatastoreInfra()
	Expect(err).ToNot(HaveOccurred())
	etcd = eds.etcdContainer

	felixes, client = StartNNodeTopology(n, opts, eds)

	return
}

// StartSingleNodeEtcdTopology starts an etcd container and a single Felix container; it initialises
// the datastore and installs a Node resource for the Felix node.
func StartSingleNodeTopology(options TopologyOptions, infra DatastoreInfra) (felix *Felix, calicoClient client.Interface) {
	felixes, calicoClient := StartNNodeTopology(1, options, infra)
	felix = felixes[0]
	return
}

// StartNNodeEtcdTopology starts an etcd container and a set of Felix hosts.  If n > 1, sets
// up IPIP, otherwise this is skipped.
//
// - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//   but (for simplicity) we don't actually use IPAM to assign IPs.
// - Configures routes between the hosts, giving each host 10.65.x.0/24, where x is the
//   index in the returned array.  When creating workloads, use IPs from the relevant block.
// - Configures the Tunnel IP for each host as 10.65.x.1.
func StartNNodeTopology(n int, opts TopologyOptions, infra DatastoreInfra) (felixes []*Felix, client client.Interface) {
	log.Infof("Starting a %d-node topology.", n)
	success := false
	var err error
	defer func() {
		if !success {
			log.WithError(err).Error("Failed to start topology, tearing down containers")
			for _, felix := range felixes {
				felix.Stop()
			}
			infra.Stop()
		}
	}()

	// Get client.
	client = infra.GetCalicoClient()
	mustInitDatastore(client)

	if n > 1 {
		Eventually(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ipPool := api.NewIPPool()
			ipPool.Name = "test-pool"
			ipPool.Spec.CIDR = "10.65.0.0/16"
			if opts.IPIPEnabled {
				ipPool.Spec.IPIPMode = api.IPIPModeAlways
			} else {
				ipPool.Spec.IPIPMode = api.IPIPModeNever
			}
			_, err = client.IPPools().Create(ctx, ipPool, options.SetOptions{})
			return err
		}).ShouldNot(HaveOccurred())
	}

	if opts.WithTypha {
		typha := RunTypha(infra, opts)
		opts.ExtraEnvVars["FELIX_TYPHAADDR"] = typha.IP + ":5473"
	}

	for i := 0; i < n; i++ {
		// Then start Felix and create a node for it.
		felix := RunFelix(infra, opts)
		if opts.IPIPEnabled {
			infra.SetExpectedIPIPTunnelAddr(felix, i, bool(n > 1))
		}

		var w chan struct{}
		if felix.ExpectedIPIPTunnelAddr != "" {
			// If felix has an IPIP tunnel address defined, Felix may restart after loading its config.
			// Handle that here by monitoring the log and waiting for the correct tunnel IP to show up
			// before we return.
			w = felix.WatchStdoutFor(regexp.MustCompile(
				`"IpInIpTunnelAddr":"` + regexp.QuoteMeta(felix.ExpectedIPIPTunnelAddr) + `"`))
		}
		infra.AddNode(felix, i, bool(n > 1))
		if w != nil {
			// Wait for any Felix restart...
			log.Info("Wait for Felix to restart")
			Eventually(w, "10s").Should(BeClosed())
		}
		felixes = append(felixes, felix)
	}

	// Set up routes between the hosts, note: we're not using IPAM here but we set up similar
	// CIDR-based routes.
	for i, iFelix := range felixes {
		for j, jFelix := range felixes {
			if i == j {
				continue
			}

			jBlock := fmt.Sprintf("10.65.%d.0/24", j)
			if opts.IPIPEnabled {
				err := iFelix.ExecMayFail("ip", "route", "add", jBlock, "via", jFelix.IP, "dev", "tunl0", "onlink")
				Expect(err).ToNot(HaveOccurred())
			} else {
				err := iFelix.ExecMayFail("ip", "route", "add", jBlock, "via", jFelix.IP, "dev", "eth0")
				Expect(err).ToNot(HaveOccurred())
			}
		}
	}
	success = true
	return
}

func mustInitDatastore(client client.Interface) {
	Eventually(func() error {
		log.Info("Initializing the datastore...")
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		err := client.EnsureInitialized(
			ctx,
			"v3.0.0-test",
			"felix-fv",
		)
		log.WithError(err).Info("EnsureInitialized result")
		return err
	}).ShouldNot(HaveOccurred(), "mustInitDatastore failed")
}
