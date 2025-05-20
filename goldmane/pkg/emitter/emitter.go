// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/goldmane/pkg/storage"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

var (
	maxRetries   = 15
	configMapKey = apitypes.NamespacedName{Name: "flow-emitter-state", Namespace: "calico-system"}
	healthName   = "emitter"
)

// Emitter is a type that emits aggregated Flow objects to an HTTP endpoint.
type Emitter struct {
	client *emitterClient

	kcli client.Client

	// Configuration for emitter endpoint.
	url        string
	caCert     string
	clientKey  string
	clientCert string
	serverName string

	// For health checking.
	health *health.HealthAggregator

	// Use a rate limited workqueue to manage bucket emission.
	buckets *bucketCache
	queue   workqueue.TypedRateLimitingInterface[bucketKey]

	// Track the latest timestamp of emitted flows. This helps us avoid emitting the same flow multiple times
	// on restart.
	latestTimestamp int64
}

// Make sure Emitter implements the Receiver interface to be able to receive aggregated Flows.
var _ storage.Sink = &Emitter{}

func NewEmitter(opts ...Option) *Emitter {
	e := &Emitter{
		buckets: newBucketCache(),
		queue: workqueue.NewTypedRateLimitingQueue(
			workqueue.NewTypedMaxOfRateLimiter(
				workqueue.NewTypedItemExponentialFailureRateLimiter[bucketKey](1*time.Second, 30*time.Second),
				&workqueue.TypedBucketRateLimiter[bucketKey]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
			)),
	}

	for _, opt := range opts {
		opt(e)
	}

	var err error
	e.client, err = newEmitterClient(e.url, e.caCert, e.clientKey, e.clientCert, e.serverName)
	if err != nil {
		log.Fatalf("Error creating emitter client: %v", err)
	}
	log.WithField("url", e.url).Info("Created emitter client.")

	if e.kcli == nil {
		log.Warn("No k8s client provided, will not be able to cache state.")
	}

	return e
}

func (e *Emitter) Run(ctx context.Context) {
	// Start by loading any state cached in our configmap, which will allow us to better pick up where we left off
	// in the event of a restart.
	if err := e.loadCachedState(); err != nil {
		log.Errorf("Error loading cached state: %v", err)
	}

	done := make(chan struct{})
	defer close(done)

	// Shutdown the emitter if the context was cancelled
	go func() {
		defer e.queue.ShutDown()
		select {
		case <-ctx.Done():
			log.Info("Context cancelled, shutting down emitter.")
		case <-done:
			log.Info("Emitter shutting down.")
		}
	}()

	if e.health != nil {
		// Register the emitter with the health aggregator. We don't use a timeout here, since the work of the
		// emitter is fully reactive to the workqueue.
		e.health.RegisterReporter(healthName, &health.HealthReport{Live: true, Ready: true}, 0)

		// Report that we're live and ready. Note that we will never mark ourselves as not ready after this point, since
		// doing so would remove this pod from Service load balancing and thus prevent it from receiving any more flows.
		e.reportHealth(&health.HealthReport{Live: true, Ready: true})
	}

	// This is the main loop for the emitter. It listens for new batches of flows to emit and emits them.
	for {
		// Get pending work from the queue.
		key, quit := e.queue.Get()
		if quit {
			log.Info("Emitter queue completed")
			return
		}
		e.queue.Done(key)

		bucket, ok := e.buckets.get(key)
		if !ok {
			log.WithField("bucket", key).Error("Bucket not found in cache.")
			e.queue.Forget(key)
			continue
		}

		// Emit the bucket.
		if err := e.emit(bucket); err != nil {
			log.Errorf("Error emitting flows to %s: %v", e.url, err)
			e.retry(key)
			continue
		}

		// Success. Remove the bucket from our internal map, and
		// clear it from the workqueue.
		if retries := e.queue.NumRequeues(key); retries > 0 {
			log.WithFields(log.Fields{
				"bucket":  key,
				"retries": retries,
			}).Info("Successfully emitted flows after retries.")
		}
		e.forget(key)
		e.reportHealth(&health.HealthReport{Live: true, Ready: true})
	}
}

func (e *Emitter) reportHealth(report *health.HealthReport) {
	if e.health != nil {
		e.health.Report(healthName, report)
	}
}

func (e *Emitter) Receive(bucket *storage.FlowCollection) {
	// Add the bucket to our internal map so we can retry it if needed.
	// We'll remove it from the map once it's successfully emitted.
	k := bucketKey{startTime: bucket.StartTime, endTime: bucket.EndTime}
	e.buckets.add(k, bucket)
	e.queue.Add(k)
}

func (e *Emitter) retry(k bucketKey) {
	if e.queue.NumRequeues(k) < maxRetries {
		log.WithField("bucket", k).Debug("Queueing retry for bucket.")
		e.queue.AddRateLimited(k)
	} else {
		log.WithField("bucket", k).Error("Max retries exceeded, dropping bucket.")
		e.forget(k)
	}
}

// forget removes a bucket from the internal cache and the workqueue, and can be called safely
// from any goroutine after a bucket has been successfully emitted, or has reached the maximum
// maximum number of retries.
func (e *Emitter) forget(k bucketKey) {
	e.buckets.remove(k)
	e.queue.Forget(k)
}

func (e *Emitter) emit(bucket *storage.FlowCollection) error {
	// Check if we have already emitted this batch. If it pre-dates
	// the latest timestamp we've emitted, skip it. This can happen, for example, on restart when
	// we learn already emitted flows from the cache.
	if bucket.EndTime <= e.latestTimestamp {
		log.WithField("bucketEndTime", bucket.EndTime).Debug("Skipping already emitted flows.")
		return nil
	}

	// Marshal the flows to JSON and send them to the emitter.
	rdr, err := e.collectionToReader(bucket)
	if err != nil {
		return err
	}
	if err := e.client.Post(rdr); err != nil {
		return err
	}

	// Update the timestamp of the latest bucket emitted.
	e.latestTimestamp = bucket.EndTime

	// Update our configmap with the latest published timestamp.
	if err = e.saveState(); err != nil {
		log.WithError(err).Warn("Error saving state.")
	}
	return nil
}

func (e *Emitter) collectionToReader(bucket *storage.FlowCollection) (*bytes.Reader, error) {
	body := []byte{}
	for _, flow := range bucket.Flows {
		if len(body) != 0 {
			// Include a separator between logs.
			body = append(body, []byte("\n")...)
		}

		// Convert to public format.
		f := types.FlowToProto(&flow)
		flowJSON, err := json.Marshal(f)
		if err != nil {
			return nil, fmt.Errorf("Error marshalling flow: %v", err)
		}
		body = append(body, flowJSON...)
	}
	return bytes.NewReader(body), nil
}

// saveState updates cached metadata stored across restart. We use a configmap to
// track the latest timestamp of emitted flows so we can pick up where we left off on reboot.
func (e *Emitter) saveState() error {
	if e.kcli == nil {
		return nil
	}
	if e.latestTimestamp == 0 {
		return nil
	}

	// Query the latest configmap.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cm := &corev1.ConfigMap{}
	if err := e.kcli.Get(ctx, configMapKey, cm); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("error getting configmap: %v", err)
	} else if errors.IsNotFound(err) {
		// Configmap doesn't exist, create it.
		cm.Name = configMapKey.Name
		cm.Namespace = configMapKey.Namespace
		cm.Data = map[string]string{}
	}

	// Update the timestamp in the configmap.
	cm.Data["latestTimestamp"] = fmt.Sprintf("%d", e.latestTimestamp)
	logCtx := log.WithFields(log.Fields{
		"cm":              configMapKey,
		"latestTimestamp": cm.Data["latestTimestamp"],
	})

	if cm.ResourceVersion == "" {
		// Create the configmap.
		if err := e.kcli.Create(context.Background(), cm); err != nil {
			return fmt.Errorf("error creating configmap: %v", err)
		}
		logCtx.Debug("Created configmap")
	} else {
		// Update the configmap.
		if err := e.kcli.Update(context.Background(), cm); err != nil {
			return fmt.Errorf("error updating configmap: %v", err)
		}
		logCtx.Debug("Updated configmap")
	}
	return nil
}

func (e *Emitter) loadCachedState() error {
	if e.kcli == nil {
		return nil
	}

	// Query the latest configmap.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cm := &corev1.ConfigMap{}
	if err := e.kcli.Get(ctx, configMapKey, cm); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("error getting configmap: %v", err)
	} else if errors.IsNotFound(err) {
		log.WithField("cm", configMapKey).Debug("Configmap not found")
		return nil
	}

	raw, ok := cm.Data["latestTimestamp"]
	if !ok {
		return nil
	}

	// Parse the timestamp from the configmap.
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("error parsing timestamp: %v", err)
	}
	e.latestTimestamp = ts
	return nil
}
