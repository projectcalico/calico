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

package syncserver

import (
	"context"
	"encoding/gob"
	"errors"
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/buildinfo"
	"github.com/projectcalico/typha/pkg/jitter"
	"github.com/projectcalico/typha/pkg/snapcache"
	"github.com/projectcalico/typha/pkg/syncproto"
)

var (
	ErrReadFailed          = errors.New("Failed to read from client")
	ErrUnexpectedClientMsg = errors.New("Unexpected message from client")
)

var (
	counterNumConnectionsAccepted = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_connections_accepted",
		Help: "Total number of connections accepted over time.",
	})
	gaugeNumConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "typha_connections_active",
		Help: "Number of open client connections.",
	})
	summarySnapshotSendTime = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_snapshot_send_secs",
		Help: "How long it took to send the initial snapshot to each client.",
	})
	summaryClientLatency = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_latency_secs",
		Help: "Per-client latency.  I.e. how far behind the current state is each client.",
		// Reduce the time window so the stat is more useful after a spike.
		MaxAge:     1 * time.Minute,
		AgeBuckets: 2,
	})
	summaryWriteLatency = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_client_write_latency_secs",
		Help: "Per-client write.  How long each write call is taking.",
	})
	summaryNextCatchupLatency = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_next_breadcrumb_latency_secs",
		Help: "Time to retrieve next breadcrumb when already behind.",
	})
	summaryPingLatency = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_ping_latency",
		Help: "Round-trip ping latency to client.",
	})
	summaryNumKVsPerMsg = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "typha_kvs_per_msg",
		Help: "Number of KV pairs sent in each message.",
	})
)

func init() {
	prometheus.MustRegister(counterNumConnectionsAccepted)
	prometheus.MustRegister(gaugeNumConnections)
	prometheus.MustRegister(summarySnapshotSendTime)
	prometheus.MustRegister(summaryClientLatency)
	prometheus.MustRegister(summaryNextCatchupLatency)
	prometheus.MustRegister(summaryWriteLatency)
	prometheus.MustRegister(summaryPingLatency)
	prometheus.MustRegister(summaryNumKVsPerMsg)
}

const (
	defaultMaxMessageSize       = 100
	defaultMaxFallBehind        = 90 * time.Second
	defaultBatchingAgeThreshold = 100 * time.Millisecond
	defaultPingInterval         = 10 * time.Second
)

type contextKey string

const CxtKeyConnID = contextKey("ConnID")

type Server struct {
	config     Config
	cache      BreadcrumbProvider
	nextConnID uint64
}

type BreadcrumbProvider interface {
	CurrentBreadcrumb() *snapcache.Breadcrumb
}

type Config struct {
	MaxMessageSize          int
	MaxFallBehind           time.Duration
	MinBatchingAgeThreshold time.Duration
	PingInterval            time.Duration
	PongTimeout             time.Duration
}

func New(cache BreadcrumbProvider, config Config) *Server {
	if config.MaxMessageSize < 1 {
		log.WithFields(log.Fields{
			"value":   config.MaxMessageSize,
			"default": defaultMaxMessageSize,
		}).Info("Defaulting MaxMessageSize.")
		config.MaxMessageSize = defaultMaxMessageSize
	}
	if config.MaxFallBehind <= 0 {
		log.WithFields(log.Fields{
			"value":   config.MaxFallBehind,
			"default": defaultMaxFallBehind,
		}).Info("Defaulting MaxFallBehind.")
		config.MaxFallBehind = defaultMaxFallBehind
	}
	if config.MaxFallBehind <= 0 {
		log.WithFields(log.Fields{
			"value":   config.MinBatchingAgeThreshold,
			"default": defaultBatchingAgeThreshold,
		}).Info("Defaulting MinBatchingAgeThreshold.")
		config.MinBatchingAgeThreshold = defaultBatchingAgeThreshold
	}
	if config.PingInterval <= 0 {
		log.WithFields(log.Fields{
			"value":   config.PingInterval,
			"default": defaultPingInterval,
		}).Info("Defaulting PingInterval.")
		config.PingInterval = defaultPingInterval
	}
	if config.PongTimeout <= config.PingInterval*2 {
		defaultTimeout := config.PongTimeout * 6
		log.WithFields(log.Fields{
			"value":   config.PongTimeout,
			"default": defaultTimeout,
		}).Info("PongTimeout < PingInterval * 2; Defaulting PongTimeout.")
		config.PongTimeout = defaultTimeout
	}

	return &Server{
		config: config,
		cache:  cache,
	}
}

func (s *Server) Serve(cxt context.Context) {
	logCxt := log.WithField("port", syncproto.DefaultPort)
	logCxt.Info("Opening listen socket")
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: syncproto.DefaultPort})
	if err != nil {
		logCxt.WithError(err).Panic("Failed to open listen socket")
	}
	logCxt.Info("Opened listen socket")
	defer l.Close()
	for {
		logCxt.Debug("About to accept connection")
		conn, err := l.AcceptTCP()
		if err != nil {
			logCxt.WithError(err).Panic("Failed to accept connection")
		}

		connID := s.nextConnID
		s.nextConnID++
		logCxt.WithField("connID", connID).Info("New connection")
		counterNumConnectionsAccepted.Inc()

		// Create a new connection-scoped context, which we'll use for signaling to our child
		// goroutines to halt.
		connCxt := context.WithValue(cxt, CxtKeyConnID, connID)
		connCxt, cancel := context.WithCancel(connCxt)
		connection := &connection{
			config:    &s.config,
			cache:     s.cache,
			cxt:       connCxt,
			cancelCxt: cancel,
			conn:      conn,
			logCxt: log.WithFields(log.Fields{
				"client": conn.RemoteAddr(),
				"connID": connID,
			}),

			encoder: gob.NewEncoder(conn),
			readC:   make(chan interface{}),
		}
		go connection.handle()
	}
}

type connection struct {
	config *Config

	// cxt is the per-connection context.
	cxt context.Context
	// cancelCxt is the cancel function for the above context.  We call this from any goroutine that's stopping
	// to make sure that everything else gets shut down.
	cancelCxt context.CancelFunc
	// shutDownWG is used to wait for our background threads to finish.
	shutDownWG sync.WaitGroup

	cache BreadcrumbProvider
	conn  *net.TCPConn

	encoder *gob.Encoder
	readC   chan interface{}

	logCxt *log.Entry
}

func (h *connection) handle() (err error) {
	// Ensure that stop gets called.  Stop will close the connection and context and wait for our background
	// goroutines to finish.
	defer func() {
		// Cancel the context and close the connection, this will trigger our background threads to shut down.
		// We need to do both because they may be blocked on IO or something else.
		h.cancelCxt()
		err := h.conn.Close()
		if err != nil {
			log.WithError(err).Error("Error when closing connection.  Ignoring!")
		}
		// Wait for the background threads to shut down.
		h.shutDownWG.Wait()
		gaugeNumConnections.Dec()
		h.logCxt.Info("Client connection shut down.")
	}()

	h.logCxt.Info("Per-connection goroutine started")
	gaugeNumConnections.Inc()

	// Start goroutine to read messages from client and put them on a channel for this goroutine to process.
	h.shutDownWG.Add(1)
	go h.readFromClient(h.logCxt.WithField("thread", "read"))

	// Now do the (synchronous) handshake before we start our update-writing thread.
	if err = h.doHandshake(); err != nil {
		return // Error already logged.
	}

	// Start a goroutine to stream the snapshot and then the deltas to the client.
	h.shutDownWG.Add(1)
	go h.sendSnapshotAndUpdatesToClient(h.logCxt.WithField("thread", "kv-sender"))

	// Start a goroutine to send periodic pings.  We send pings from their own goroutine so that, if the Encoder
	// blocks, we don't prevent the main goroutine from checking the pongs.
	h.shutDownWG.Add(1)
	go h.sendPingsToClient(h.logCxt.WithField("thread", "pinger"))

	// Start a ticker to check that we receive pongs in a timely fashion.
	pongTicker := jitter.NewTicker(h.config.PingInterval/2, h.config.PingInterval/10)
	defer pongTicker.Stop()
	lastPongReceived := time.Now()

	// Use this goroutine to wait for client messages and do the ping/pong liveness check.
	h.logCxt.Info("Waiting for messages from client")
	for {
		select {
		case msg := <-h.readC:
			if msg == nil {
				h.logCxt.Info("Read channel ended")
				return h.cxt.Err()
			}
			switch msg := msg.(type) {
			case syncproto.MsgPong:
				h.logCxt.Debug("Pong from client")
				lastPongReceived = time.Now()
				summaryPingLatency.Observe(time.Since(msg.PingTimestamp).Seconds())
			default:
				h.logCxt.WithField("msg", msg).Error("Unknown message from client")
				return errors.New("Unknown message type")
			}
		case <-pongTicker.C:
			if time.Since(lastPongReceived) > h.config.PongTimeout {
				h.logCxt.Info("Too long since last pong from client, disconnecting")
				return errors.New("No pong received from client")
			}
		case <-h.cxt.Done():
			h.logCxt.Info("Asked to stop by Context.")
			return h.cxt.Err()
		}
	}
}

// readFromClient reads messages from the client and puts them on the h.readC channel.  It is responsible for closing the
// channel.
func (h *connection) readFromClient(logCxt *log.Entry) {
	defer func() {
		h.cancelCxt()
		close(h.readC)
		h.shutDownWG.Done()
		logCxt.Info("Read goroutine finished")
	}()
	r := gob.NewDecoder(h.conn)
	for {
		var envelope syncproto.Envelope
		err := r.Decode(&envelope)
		if err != nil {
			logCxt.WithError(err).Info("Failed to read from client")
			break
		}
		if envelope.Message == nil {
			log.Error("nil message from client")
			break
		}
		select {
		case h.readC <- envelope.Message:
		case <-h.cxt.Done():
			return
		}

	}
}

// waitForMessage blocks, waiting for a message on the h.readC channel.  It imposes a timeout.
func (h *connection) waitForMessage(logCxt *log.Entry) (interface{}, error) {
	// Read the hello message from the client.
	cxt, cancel := context.WithDeadline(h.cxt, time.Now().Add(60*time.Second))
	defer cancel()
	select {
	case msg := <-h.readC:
		if msg == nil {
			logCxt.Warning("Failed to read hello from client")
			return nil, ErrReadFailed
		}
		logCxt.WithField("msg", msg).Debug("Received message from client.")
		return msg, nil
	case <-cxt.Done():
		logCxt.Info("Asked to stop by context.")
		return nil, h.cxt.Err()
	}
}

func (h *connection) doHandshake() error {
	// Read the client's hello message.
	msg, err := h.waitForMessage(h.logCxt)
	if err != nil {
		h.logCxt.WithError(err).Warn("Failed to read client hello.")
		return err
	}
	hello, ok := msg.(syncproto.MsgClientHello)
	if !ok {
		h.logCxt.WithField("msg", msg).Error("Unexpected message from client.")
		return ErrUnexpectedClientMsg
	}
	h.logCxt.WithField("msg", hello).Info("Received Hello message from client.")

	// Respond to client's hello.
	err = h.sendMsg(syncproto.MsgServerHello{
		Version: buildinfo.GitVersion,
	})
	if err != nil {
		log.WithError(err).Warning("Failed to send hello to client")
		return err
	}
	return nil
}

// sendMsg sends a message to the client.  It may be called from multiple goroutines because the Encoder is thread-safe.
func (h *connection) sendMsg(msg interface{}) error {
	if h.cxt.Err() != nil {
		// Optimisation, don't bother to send if we're being torn down.
		return h.cxt.Err()
	}
	envelope := syncproto.Envelope{
		Message: msg,
	}
	startTime := time.Now()
	err := h.encoder.Encode(&envelope)
	if err != nil {
		h.logCxt.WithError(err).Info("Failed to write to client")
		return err
	}
	summaryWriteLatency.Observe(time.Since(startTime).Seconds())
	return nil
}

// sendSnapshotAndUpdatesToClient sends the snapshot from the current Breadcrumb and then follows the Breadcrumbs
// sending deltas to the client.
func (h *connection) sendSnapshotAndUpdatesToClient(logCxt *log.Entry) {
	defer func() {
		h.cancelCxt()
		h.shutDownWG.Done()
		logCxt.Info("KV-sender goroutine finished")
	}()

	// Get the current snapshot and stream it to the client...
	breadcrumb := h.cache.CurrentBreadcrumb()
	h.streamSnapshotToClient(logCxt, breadcrumb)

	// Track the sync status reported in each Breadcrumb so we can send an update if it changes.
	var lastSentStatus api.SyncStatus
	maybeSendStatus := func() (err error) {
		if lastSentStatus != breadcrumb.SyncStatus {
			logCxt.WithField("newStatus", breadcrumb.SyncStatus).Info(
				"Status update to send.")
			err = h.sendMsg(syncproto.MsgSyncStatus{
				SyncStatus: breadcrumb.SyncStatus,
			})
			if err != nil {
				logCxt.WithError(err).Info("Failed to send status to client")
				return
			}
			lastSentStatus = breadcrumb.SyncStatus
		}
		return
	}

	// The first Breadcrumb may have changed the status.  Send an update if so.
	if err := maybeSendStatus(); err != nil {
		return
	}

	for h.cxt.Err() == nil {
		// Wait for new Breadcrumbs.  If we're behind, we'll coalesce the deltas from multiple Breadcrumbs
		// before exiting the loop.
		var deltas []syncproto.SerializedUpdate
		for len(deltas) < h.config.MaxMessageSize {
			// Get the next breadcrumb.  This may block.
			nextStartTime := time.Now()
			var err error
			breadcrumb, err = breadcrumb.Next(h.cxt)
			if err != nil {
				logCxt.WithError(err).Info("Getting next Breadcrumb canceled by context.")
				return
			}
			timeSpentInNext := time.Since(nextStartTime)
			logCxt.WithFields(log.Fields{
				"seqNo":     breadcrumb.SequenceNumber,
				"timestamp": breadcrumb.Timestamp,
			}).Debug("New Breadcrumb")

			// Take a peek at the very latest breadcrumb to see how far behind we are...
			latestCrumb := h.cache.CurrentBreadcrumb()
			crumbAge := latestCrumb.Timestamp.Sub(breadcrumb.Timestamp)
			summaryClientLatency.Observe(crumbAge.Seconds())

			// Check if we're too far behind the latest Breadcrumb.
			if crumbAge > h.config.MaxFallBehind {
				logCxt.WithFields(log.Fields{
					"snapAge":     crumbAge,
					"mySeqNo":     breadcrumb.SequenceNumber,
					"latestSeqNo": latestCrumb.SequenceNumber,
				}).Warn("Client fell behind. Disconnecting.")
				return
			}

			if crumbAge < h.config.MinBatchingAgeThreshold && deltas == nil {
				// We're not behind and we haven't already started to batch up updates.  Avoid
				// copying the deltas and just send them
				deltas = breadcrumb.Updates
				break
			}

			// Either we're already batching up updates or we're behind.  Append the deltas to the
			// buffer.
			deltas = append(deltas, breadcrumb.Updates...)
			summaryNextCatchupLatency.Observe(timeSpentInNext.Seconds())

			if crumbAge < h.config.MinBatchingAgeThreshold {
				// Caught up, stop batching.
				break
			}
		}

		if len(deltas) > 0 {
			// Send the deltas relative to the previous snapshot.
			summaryNumKVsPerMsg.Observe(float64(len(deltas)))
			err := h.sendMsg(syncproto.MsgKVs{
				KVs: deltas,
			})
			if err != nil {
				logCxt.WithError(err).Info("Failed to send to client.")
				return
			}
		}

		// Newest breadcrumb may have updated the sync status, send an update if so.
		if err := maybeSendStatus(); err != nil {
			return
		}
	}
}

// streamSnapshotToClient takes the snapshot contained in the Breadcrumb and streams it to the client in chunks.
func (h *connection) streamSnapshotToClient(logCxt *log.Entry, breadcrumb *snapcache.Breadcrumb) (err error) {
	logCxt = logCxt.WithFields(log.Fields{
		"seqNo":  breadcrumb.SequenceNumber,
		"status": breadcrumb.SyncStatus,
	})
	logCxt.Info("Starting to send snapshot to client")
	startTime := time.Now()

	// Get an iterator for the snapshot. cancelC is used to ensure that the iterator's goroutine gets cleaned up.
	cancelC := make(chan struct{})
	defer close(cancelC)
	iter := breadcrumb.KVs.Iterator(cancelC)

	// sendKVs is a utility function that sends the kvs buffer to the client and clears the buffer.
	var kvs []syncproto.SerializedUpdate
	var numKeys int
	sendKVs := func() error {
		if len(kvs) == 0 {
			return nil
		}
		logCxt.WithField("numKVs", len(kvs)).Debug("Sending snapshot KVs to client.")
		numKeys += len(kvs)
		summaryNumKVsPerMsg.Observe(float64(len(kvs)))
		err := h.sendMsg(syncproto.MsgKVs{
			KVs: kvs,
		})
		if err != nil {
			logCxt.WithError(err).Info("Failed to send to client")
		}
		kvs = kvs[:0]
		return err
	}

	for {
		select {
		case entry := <-iter:
			if entry == nil {
				// End of the iterator.  Make sure we send the last batch, if there is one...
				err = sendKVs()
				logCxt.WithField("numKeys", numKeys).Info("Finished sending snapshot to client")
				summarySnapshotSendTime.Observe(time.Since(startTime).Seconds())
				return
			}
			kvs = append(kvs, entry.Value.(syncproto.SerializedUpdate))
			if len(kvs) >= h.config.MaxMessageSize {
				// Buffer is full, send the next batch.
				err = sendKVs()
				if err != nil {
					return
				}
			}
		case <-h.cxt.Done():
			err = h.cxt.Err()
			logCxt.WithError(err).Info("Asked to stop by Context")
			return
		}
	}
}

// sendPingsToClient loops, sending pings to the client at the configured interval.
func (h *connection) sendPingsToClient(logCxt *log.Entry) {
	defer func() {
		h.cancelCxt()
		h.shutDownWG.Done()
		logCxt.Info("Pinger goroutine shut down.")
	}()
	pingTicker := jitter.NewTicker(h.config.PingInterval, h.config.PingInterval/10)
	defer pingTicker.Stop()
	for {
		select {
		case <-pingTicker.C:
			logCxt.Debug("Sending ping.")
			err := h.sendMsg(syncproto.MsgPing{
				Timestamp: time.Now(),
			})
			if err != nil {
				log.WithError(err).Info("Failed to send ping to client")
				return
			}
		case <-h.cxt.Done():
			log.WithError(h.cxt.Err()).Info("Context was canceled.")
			return
		}
	}
}
