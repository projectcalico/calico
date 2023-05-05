// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.
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

package windataplane

import (
	"math"
	"regexp"
	"time"

	"github.com/projectcalico/calico/felix/dataplane/windows/hcn"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dataplane/windows/hns"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/dataplane/windows/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/windows/policysets"
	"github.com/projectcalico/calico/felix/jitter"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/throttle"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	// msgPeekLimit is the maximum number of messages we'll try to grab from the to-dataplane
	// channel before we apply the changes.  Higher values allow us to batch up more work on
	// the channel for greater throughput when we're under load (at cost of higher latency).
	msgPeekLimit = 100

	// After a failure to apply dataplane updates, we will delay for this amount of time
	// before rescheduling another attempt to apply the pending updates.
	reschedDelay = time.Duration(5) * time.Second
)

var (
	processStartTime time.Time
)

func init() {
	processStartTime = time.Now()
}

type Config struct {
	IPv6Enabled      bool
	HealthAggregator *health.HealthAggregator

	// Currently set to maximum value.
	MaxIPSetSize int

	Hostname     string
	VXLANEnabled bool
	VXLANID      int
	VXLANPort    int
}

// winDataplane implements an in-process Felix dataplane driver capable of applying network policy
// dataplane updates via the Host Network Service (HNS) on Windows. It communicates with the
// datastore-facing part of Felix via the Send/RecvMessage methods, which operate on the
// protobuf-defined API objects.
//
// # Architecture
//
// The Windows dataplane driver is organised around a main event loop, which handles
// update events from the datastore and dataplane.
//
// Each pass around the main loop has two phases.  In the first phase, updates are fanned
// out to "manager" objects, which calculate the changes that are needed. In the second phase,
// the set of pending changes are communicated to the HNS service so that they will be immediately
// applied to the dataplane. The second phase is skipped until the datastore is in sync; this
// ensures that the first update to the dataplane applies a consistent snapshot.
//
// Several optimizations and improvements are forthcoming. At this time, the Windows dataplane does
// not have a native concept similar to IP sets, which means that IP set information needs to be
// cached in the driver along with associated Policies/Profiles. As datastore updates are received,
// we refer back to the caches to recalculate the sets of rules which need to be sent to HNS. As the
// HNS API surface is enhanced, we may be able to optimize and remove some or all of these caches.
//
// # Requirements on the API
//
// The dataplane does not do consistency checks on the incoming data. It expects to be told about
// dependent resources before they are needed and for their lifetime to exceed that of the resources
// that depend on them.  For example, it is important the the datastore layer send an IP set create
// event before it sends a rule that references that IP set.
type WindowsDataplane struct {
	// the channel which we receive messages from felix
	toDataplane chan interface{}
	// the channel used to send messages from the dataplane to felix
	fromDataplane chan interface{}
	// ifaceAddrUpdates is a channel used to signal when the host's IPs change.
	ifaceAddrUpdates chan []string
	// stores all of the managers which will be processing  the various updates from felix.
	allManagers []Manager
	endpointMgr *endpointManager
	// each IPSets manages a whole "plane" of IP sets, i.e. all the IPv4 sets, or all the IPv6
	// IP sets.
	ipSets []*ipsets.IPSets
	// PolicySets manages all of the policies and profiles which have been communicated to the
	// dataplane driver
	policySets *policysets.PolicySets
	// dataplaneNeedsSync is set if the dataplane is dirty in some way, i.e. we need to
	// call apply().
	dataplaneNeedsSync bool
	// doneFirstApply is set after we finish the first update to the dataplane. It indicates
	// that the dataplane should now be in sync.
	doneFirstApply bool
	// the reschedule timer/channel enable us to force the dataplane driver to attempt to
	// apply any pending updates to the dataplane. This is only enabled and used if a previous
	// apply operation has failed and needs to be retried.
	reschedTimer *time.Timer
	reschedC     <-chan time.Time
	// a simple throttle to control how frequently the driver is allowed to apply updates
	// to the dataplane.
	applyThrottle *throttle.Throttle
	// config provides a way for felix to provide some additional configuration options
	// to the dataplane driver. This isn't really used currently, but will be in the future.
	config Config
}

const (
	healthName     = "win_dataplane"
	healthInterval = 10 * time.Second
)

// Interface for Managers. Each Manager is responsible for processing updates from felix and
// for applying any necessary updates to the dataplane.
type Manager interface {
	// OnUpdate is called for each protobuf message from the datastore.  May either directly
	// send updates to the IPSets and PolicySets objects (which will queue the updates
	// until the main loop instructs them to act) or (for efficiency) may wait until
	// a call to CompleteDeferredWork() to flush updates to the dataplane.
	OnUpdate(protoBufMsg interface{})
	// Called to allow for any batched work to be completed.
	CompleteDeferredWork() error
}

// Registers a new Manager with the driver.
func (d *WindowsDataplane) RegisterManager(mgr Manager) {
	d.allManagers = append(d.allManagers, mgr)
}

// NewWinDataplaneDriver creates and initializes a new dataplane driver using the provided
// configuration.
func NewWinDataplaneDriver(hns hns.API, config Config) *WindowsDataplane {
	log.WithField("config", config).Info("Creating Windows dataplane driver.")

	ipSetsConfigV4 := ipsets.NewIPVersionConfig(
		ipsets.IPFamilyV4,
	)

	ipSetsV4 := ipsets.NewIPSets(ipSetsConfigV4)
	config.MaxIPSetSize = math.MaxInt64

	dp := &WindowsDataplane{
		toDataplane:      make(chan interface{}, msgPeekLimit),
		fromDataplane:    make(chan interface{}, 100),
		ifaceAddrUpdates: make(chan []string, 1),
		config:           config,
		applyThrottle:    throttle.New(10),
	}

	dp.applyThrottle.Refill() // Allow the first apply() immediately.

	dp.ipSets = append(dp.ipSets, ipSetsV4)

	var ipsc []policysets.IPSetCache
	for _, i := range dp.ipSets {
		ipsc = append(ipsc, i)
	}
	dp.policySets = policysets.NewPolicySets(hns, ipsc, policysets.FileReader(policysets.StaticFileName))

	dp.RegisterManager(common.NewIPSetsManager(ipSetsV4, config.MaxIPSetSize))
	dp.RegisterManager(newPolicyManager(dp.policySets))
	dp.endpointMgr = newEndpointManager(hns, dp.policySets)
	dp.RegisterManager(dp.endpointMgr)
	ipSetsV4.SetCallback(dp.endpointMgr.OnIPSetsUpdate)
	if config.VXLANEnabled {
		log.Info("VXLAN enabled, starting the VXLAN manager")
		dp.RegisterManager(newVXLANManager(
			hcn.API{},
			config.Hostname,
			regexp.MustCompile(defaultNetworkName), // FIXME Hard-coded regex
			config.VXLANID,
			config.VXLANPort,
		))
	} else {
		log.Info("VXLAN disabled, not starting the VXLAN manager")
	}

	// Register that we will report liveness and readiness.
	if config.HealthAggregator != nil {
		log.Info("Registering to report health.")
		config.HealthAggregator.RegisterReporter(
			healthName,
			&health.HealthReport{Live: true, Ready: true},
			healthInterval*2,
		)
	}

	return dp
}

// Starts the driver.
func (d *WindowsDataplane) Start() {
	go d.loopUpdatingDataplane()
	go loopPollingForInterfaceAddrs(d.ifaceAddrUpdates)
}

// Called by someone to put a message into our channel so that the loop will pick it up
// and process it.
func (d *WindowsDataplane) SendMessage(msg interface{}) error {
	log.Debugf("WindowsDataPlane->SendMessage to felix: %T", msg)

	d.toDataplane <- msg
	return nil
}

// Called by Felix.go so that it can receive a channel to listen for message being
// sent by this dataplane driver.
func (d *WindowsDataplane) RecvMessage() (interface{}, error) {
	log.Debug("WindowsDataPlane->RecvMessage was invoked")

	return <-d.fromDataplane, nil
}

// The main loop which is responsible for picking up any updates and providing them
// to the managers for processing. After managers have had a chance to process the updates
// the loop will call Apply() to actually apply changes to the dataplane.
func (d *WindowsDataplane) loopUpdatingDataplane() {
	log.Debug("Started windows dataplane driver loop")

	healthTicks := time.NewTicker(healthInterval).C
	d.reportHealth()

	// Fill the apply throttle leaky bucket.
	throttleC := jitter.NewTicker(100*time.Millisecond, 10*time.Millisecond).Channel()
	beingThrottled := false

	datastoreInSync := false

	// function to pass messages to the managers for processing
	processMsgFromCalcGraph := func(msg interface{}) {
		log.WithField("msg", proto.MsgStringer{Msg: msg}).Infof(
			"Received %T update from calculation graph", msg)
		for _, mgr := range d.allManagers {
			mgr.OnUpdate(msg)
		}
		switch msg.(type) {
		case *proto.InSync:
			log.WithField("timeSinceStart", time.Since(processStartTime)).Info(
				"Datastore in sync, flushing the dataplane for the first time...")
			datastoreInSync = true
		}
	}

	for {
		select {
		case msg := <-d.toDataplane:
			// Process the message we received, then opportunistically process any other
			// pending messages.
			batchSize := 1
			processMsgFromCalcGraph(msg)
		msgLoop1:
			for i := 0; i < msgPeekLimit; i++ {
				select {
				case msg := <-d.toDataplane:
					processMsgFromCalcGraph(msg)
					batchSize++
				default:
					// Channel blocked so we must be caught up.
					break msgLoop1
				}
			}
			d.dataplaneNeedsSync = true
		case upd := <-d.ifaceAddrUpdates:
			d.endpointMgr.OnHostAddrsUpdate(upd)
		case <-throttleC:
			d.applyThrottle.Refill()
		case <-healthTicks:
			d.reportHealth()
		case <-d.reschedC:
			log.Debug("Reschedule kick received")
			d.dataplaneNeedsSync = true
			d.reschedC = nil
		}

		if datastoreInSync && d.dataplaneNeedsSync {
			// Dataplane is out-of-sync, check if we're throttled.
			if d.applyThrottle.Admit() {
				if beingThrottled && d.applyThrottle.WouldAdmit() {
					log.Info("Dataplane updates no longer throttled")
					beingThrottled = false
				}
				log.Info("Applying dataplane updates")
				applyStart := time.Now()

				// Actually apply the changes to the dataplane.
				d.apply()

				applyTime := time.Since(applyStart)
				log.WithField("msecToApply", applyTime.Seconds()*1000.0).Info(
					"Finished applying updates to dataplane.")

				if !d.doneFirstApply {
					log.WithField(
						"secsSinceStart", time.Since(processStartTime).Seconds(),
					).Info("Completed first update to dataplane.")
					d.doneFirstApply = true
				}

				d.reportHealth()
			} else {
				if !beingThrottled {
					log.Info("Dataplane updates throttled")
					beingThrottled = true
				}
			}
		}
	}
}

// Applies any pending changes to the dataplane by giving each of the managers a chance to
// complete their deferred work. If the operation fails, then this will also set up a
// rescheduling kick so that the apply can be reattempted.
func (d *WindowsDataplane) apply() {
	// Unset the needs-sync flag, a rescheduling kick will reset it later if something failed
	d.dataplaneNeedsSync = false

	// Allow each of the managers to complete any deferred work.
	scheduleRetry := false
	for _, mgr := range d.allManagers {
		err := mgr.CompleteDeferredWork()
		if err != nil {
			// schedule a retry
			log.WithError(err).Warning("CompleteDeferredWork returned an error - scheduling a retry")
			scheduleRetry = true
		}
	}

	// Set up any needed rescheduling kick.
	if d.reschedC != nil {
		// We have an active rescheduling timer, stop it so we can restart it with a
		// different timeout below if it is still needed.
		if !d.reschedTimer.Stop() {
			// Timer had already popped, drain its channel.
			<-d.reschedC
		}
		// Nil out our copy of the channel to record that the timer is inactive.
		d.reschedC = nil
	}

	if scheduleRetry {
		if d.reschedTimer == nil {
			// First time, create the timer.
			d.reschedTimer = time.NewTimer(reschedDelay)
		} else {
			// Have an existing timer, reset it.
			d.reschedTimer.Reset(reschedDelay)
		}

		d.reschedC = d.reschedTimer.C
	}
}

// Invoked periodically to report health (liveness/readiness)
func (d *WindowsDataplane) reportHealth() {
	if d.config.HealthAggregator != nil {
		d.config.HealthAggregator.Report(
			healthName,
			&health.HealthReport{Live: true, Ready: d.doneFirstApply},
		)
	}
}
