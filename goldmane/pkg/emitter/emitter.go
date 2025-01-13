package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/goldmane/pkg/aggregator"
)

var (
	queueDepth   = 1000
	configMapKey = types.NamespacedName{Name: "flow-emitter-state", Namespace: "calico-system"}
)

// Emitter is a type that emits aggregated Flow objects to an HTTP endpoint.
type Emitter struct {
	client *emitterClient

	kcli client.Client

	inputChan chan *aggregator.AggregationBucket
	retryChan chan *aggregator.AggregationBucket

	// Configuration for emitter endpoint.
	url        string
	caCert     string
	clientKey  string
	clientCert string
	serverName string

	// Track the latest timestamp of emitted flows. This helps us avoid emitting the same flow multiple times
	// on restart.
	latestTimestamp int64
}

// Make sure Emitter implements the Receiver interface to be able to receive aggregated Flows.
var _ aggregator.Sink = &Emitter{}

func NewEmitter(opts ...Option) *Emitter {
	e := &Emitter{
		inputChan: make(chan *aggregator.AggregationBucket, queueDepth),
		retryChan: make(chan *aggregator.AggregationBucket, queueDepth),
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
	// Start by loading the latest timestamp from the configmap.
	if err := e.loadCachedState(); err != nil {
		logrus.Errorf("Error loading cached state: %v", err)
	}
	for {
		select {
		case bucket := <-e.inputChan:
			if err := e.emit(bucket); err != nil {
				logrus.Errorf("Error emitting flows to %s: %v", e.url, err)

				// TODO: This is a bit of a hack to retry the batch at the end of the queue.
				// Ideally we'd retry sooner with a backoff and limit the number of retries before dropping.
				e.retry(bucket)
			}
		case flows := <-e.retryChan:
			if err := e.emit(flows); err != nil {
				logrus.Errorf("Error emitting flows on retry: %v", err)
			}
		case <-stopCh:
			return
		}
	}
}

func (e *Emitter) Receive(bucket *aggregator.AggregationBucket) {
	select {
	case e.inputChan <- bucket:
		logrus.WithField("numFlows", len(bucket.Flows)).Debug("Received batch of flows.")
		return
	default:
		oldBatch := <-e.inputChan
		e.inputChan <- bucket
		logrus.WithField("numFlows", len(oldBatch.Flows)).Warn("Dropping oldest flows due to full queue!")
	}
}

func (e *Emitter) retry(bucket *aggregator.AggregationBucket) {
	go func(bucket *aggregator.AggregationBucket) {
		time.Sleep(5 * time.Second)
		logrus.WithField("numFlows", len(bucket.Flows)).Warn("Retrying batch of flows after delay.")
		select {
		case e.retryChan <- bucket:
			return
		default:
			logrus.WithField("numFlows", len(bucket.Flows)).Warn("Dropping flows due to full retry queue!")
		}
	}(bucket)
}

func (e *Emitter) emit(bucket *aggregator.AggregationBucket) error {
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
	e.saveState()
	return nil
}

func (e *Emitter) bucketToReader(bucket *aggregator.AggregationBucket) (*bytes.Reader, error) {
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
	cm := &corev1.ConfigMap{}
	if err := e.kcli.Get(context.TODO(), configMapKey, cm); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("error getting configmap: %v", err)
	} else if errors.IsNotFound(err) {
		// Configmap doesn't exist, create it.
		cm.Name = configMapKey.Name
		cm.Namespace = configMapKey.Namespace
		cm.Data = map[string]string{}
	}

	// Update the timestamp in the configmap.
	cm.Data["latestTimestamp"] = fmt.Sprintf("%d", e.latestTimestamp)

	if cm.ResourceVersion == "" {
		// Create the configmap.
		if err := e.kcli.Create(context.Background(), cm); err != nil {
			return fmt.Errorf("error creating configmap: %v", err)
		}
	} else {
		// Update the configmap.
		if err := e.kcli.Update(context.Background(), cm); err != nil {
			return fmt.Errorf("error updating configmap: %v", err)
		}
	}
	return nil
}

func (e *Emitter) loadCachedState() error {
	if e.kcli == nil {
		return nil
	}

	// Query the latest configmap.
	cm := &corev1.ConfigMap{}
	if err := e.kcli.Get(context.TODO(), configMapKey, cm); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("error getting configmap: %v", err)
	} else if errors.IsNotFound(err) {
		// Configmap doesn't exist, nothing to load.
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
