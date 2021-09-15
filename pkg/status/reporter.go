// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package status

import (
	"context"
	"fmt"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/options"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

// Interface for a component to populate its status to node status resource.
type statusPopulator interface {
	Populate(status *apiv3.CalicoNodeStatus) error
	Show()
}

// reporter contains all the data/method about reporting back node status based on a single node status resource.
// Each reporter has a goroutine which constantly reads node status and updates node status resource.
type reporter struct {
	// The name of the node status resource.
	name string

	// Internal client to operate on node status resource.
	client client.Interface

	// buffered channel to receive updates for the resource.
	ch chan *apiv3.CalicoNodeStatus

	// status holds latest version of node status resource.
	status *apiv3.CalicoNodeStatus

	// Interval and Time ticker that node status should be reported.
	interval int
	ticker   *time.Ticker

	// populators
	populators map[BirdConnType]map[apiv3.NodeStatusClassType]statusPopulator

	// channel to indicate this reporter is not needed anymore.
	// It should start termination process.
	done chan struct{}

	// channel to indicate this reporter is terminated.
	term chan struct{}
}

// newReporter creates a reporter and start running a goroutine handling resource update.
func newReporter(name string, client client.Interface, intervalInSeconds int, populators map[BirdConnType]map[apiv3.NodeStatusClassType]statusPopulator) *reporter {
	r := &reporter{
		name:       name,
		client:     client,
		ch:         make(chan *apiv3.CalicoNodeStatus, 10),
		populators: populators,
		done:       make(chan struct{}),
	}

	r.checkAndUpdateTicker(intervalInSeconds)

	go r.run()
	return r
}

// Check and set new ticker for the reporter.
// Make sure stop the old one first to GC old ticker.
func (r reporter) checkAndUpdateTicker(interval int) {
	if r.interval == interval {
		// no update needed.
		return
	}
	if r.ticker != nil {
		r.ticker.Stop()
	}
	r.interval = interval
	r.ticker = time.NewTicker(time.Duration(interval) * time.Second)
}

// Cleanup resources owned by this reporter.
func (r reporter) cleanup() {
	r.ticker.Stop()
}

// KillAndWait sends done signal to reporter goroutine and wait until the
// goroutine of the reporter terminated.
func (r reporter) KillAndWait() {
	r.done <- struct{}{}
	<-r.term
}

// Called when the caller needs to send a new version of request.
func (r reporter) RequestUpdate(request *apiv3.CalicoNodeStatus) {
	r.ch <- request
}

// run is the main reporting loop, it loops until done.
func (r reporter) run() {
	runImmediately := make(chan struct{})

	for {
		select {
		case latest := <-r.ch:
			// Received an update of node status resource.
			if latest.Name != r.name {
				log.Warningf("node status reporter (%s) receive request with different name (%s), ignore it", r.name, latest.Name)
			} else {
				r.status = latest
				r.checkAndUpdateTicker(latest.Spec.UpdateIntervalInSeconds)
				// kick start node status update
				runImmediately <- struct{}{}
			}
		case <-runImmediately:
		case <-r.ticker.C:
			if r.status == nil {
				log.Warningf("No request found for node status reporter (%s)", r.name)
			} else {
				r.reportStatus()
			}
		case <-r.done:
			r.cleanup()
			r.term <- struct{}{}
			return
		}
	}
}

// reportStatus queries Bird or other components and update node status resource.
func (r reporter) reportStatus() {
	var err error
	// The idea here is that we either update everything successfully or we update nothing.

	// Make a local copy first.
	status := *r.status

	needUpdate := false
	for _, ipv := range []BirdConnType{BirdConnTypeV4, BirdConnTypeV6} {
		failed := false
		// Populate status from registered populators.
		for _, class := range r.status.Spec.Classes {
			if p, ok := r.populators[ipv][class]; ok {
				err := p.Populate(&status)
				if err != nil {
					// If we hit error on one BirdConnType, continue with other BirdConnTypes.
					log.WithError(err).Errorf("failed to populate status for ipv%s class %s", string(ipv), string(class))
					failed = true
					break
				}
			} else {
				log.Warningf("Wrong class (%s) requested for node status reporter (%s)", class, r.name)
			}
		}

		if !failed {
			needUpdate = true
		}
	}

	if !needUpdate {
		// Failed for all BirdConnTypes.
		return
	}

	if reflect.DeepEqual(status, *r.status) {
		// Nothing has changes since last time we updated.
		return
	}

	// Update resource
	timeout := time.After(3 * time.Second)
	for {
		select {
		case <-timeout:
			err = fmt.Errorf("timed out patching node status, last error was: %s", err.Error())
			log.WithError(err).Warn("failed to report node status")
			return
		default:
			status.Status.LastUpdated = metav1.Time{Time: time.Now()}
			_, err = r.client.CalicoNodeStatus().Update(context.Background(), &status, options.SetOptions{})
			if err != nil {
				log.WithError(err).Warnf("Failed to update node status resource; will retry")
			} else {
				// Success!
				r.status = &status
				return
			}
		}
	}
}
