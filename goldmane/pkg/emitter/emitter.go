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

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
)

var (
	maxRetries   = 15
	configMapKey = types.NamespacedName{Name: "flow-emitter-state", Namespace: "calico-system"}
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

	// Use a rate limited workqueue to manage bucket emission.
	buckets *bucketCache
	q       workqueue.TypedRateLimitingInterface[bucketKey]

	// Track the latest timestamp of emitted flows. This helps us avoid emitting the same flow multiple times
	// on restart.
	latestTimestamp int64
}

// Make sure Emitter implements the Receiver interface to be able to receive aggregated Flows.
var _ aggregator.Sink = &Emitter{}

func NewEmitter(opts ...Option) *Emitter {
	e := &Emitter{
		buckets: newBucketCache(),
		q: workqueue.NewTypedRateLimitingQueue(
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
		logrus.Fatalf("Error creating emitter client: %v", err)
	}
	logrus.WithField("url", e.url).Info("Created emitter client.")

	if e.kcli == nil {
		logrus.Warn("No k8s client provided, will not be able to cache state.")
	}

	return e
}

func (e *Emitter) Run(stopCh chan struct{}) {
	// Start by loading any state cached in our configmap, which will allow us to better pick up where we left off
	// in the event of a restart.
	if err := e.loadCachedState(); err != nil {
		logrus.Errorf("Error loading cached state: %v", err)
	}

	// This is the main loop for the emitter. It listens for new batches of flows to emit and emits them.
	for {
		// Get pending work from the queue.
		key, quit := e.q.Get()
		if quit {
			logrus.WithField("cm", configMapKey).Info("Emitter shutting down.")
			return
		}
		e.q.Done(key)

		bucket, ok := e.buckets.get(key)
		if !ok {
			logrus.WithField("bucket", key).Error("Bucket not found in cache.")
			e.q.Forget(key)
			continue
		}

		// Emit the bucket.
		if err := e.emit(bucket); err != nil {
			logrus.Errorf("Error emitting flows to %s: %v", e.url, err)
			e.retry(key)
			continue
		}

		// Success. Remove the bucket from our internal map, and
		// clear it from the workqueue.
		e.forget(key)
	}
}

func (e *Emitter) Receive(bucket *aggregator.FlowCollection) {
	// Add the bucket to our internal map so we can retry it if needed.
	// We'll remove it from the map once it's successfully emitted.
	k := bucketKey{startTime: bucket.StartTime, endTime: bucket.EndTime}
	e.buckets.add(k, bucket)
	e.q.Add(k)
}

func (e *Emitter) retry(k bucketKey) {
	if e.q.NumRequeues(k) < maxRetries {
		logrus.WithField("bucket", k).Debug("Queueing retry for bucket.")
		e.q.AddRateLimited(k)
	} else {
		logrus.WithField("bucket", k).Error("Max retries exceeded, dropping bucket.")
		e.forget(k)
	}
}

// forget removes a bucket from the internal cache and the workqueue, and can be called safely
// from any goroutine after a bucket has been successfully emitted, or has reached the maximum
// maximum number of retries.
func (e *Emitter) forget(k bucketKey) {
	e.buckets.remove(k)
	e.q.Forget(k)
}

func (e *Emitter) emit(bucket *aggregator.FlowCollection) error {
	// Check if we have already emitted this batch. If it pre-dates
	// the latest timestamp we've emitted, skip it. This can happen, for example, on restart when
	// we learn already emitted flows from the cache.
	if bucket.EndTime <= e.latestTimestamp {
		logrus.WithField("bucketEndTime", bucket.EndTime).Debug("Skipping already emitted flows.")
		return nil
	}

	// Marshal the flows to JSON and send them to the emitter.
	rdr, err := e.bucketToReader(bucket)
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
		logrus.WithError(err).Warn("Error saving state.")
	}
	return nil
}

func (e *Emitter) bucketToReader(bucket *aggregator.FlowCollection) (*bytes.Reader, error) {
	body := []byte{}
	for _, flow := range bucket.Flows {
		if len(body) != 0 {
			// Include a separator between logs.
			body = append(body, []byte("\n")...)
		}

		flowJSON, err := json.Marshal(flow)
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
	logCtx := logrus.WithFields(logrus.Fields{
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
		logrus.WithField("cm", configMapKey).Debug("Configmap not found")
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
