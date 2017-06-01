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
	"errors"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"

	"encoding/gob"

	"github.com/prometheus/client_golang/prometheus"

	"sync"

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/typha/pkg/buildinfo"
	"github.com/projectcalico/typha/pkg/jitter"
	"github.com/projectcalico/typha/pkg/snapcache"
	"github.com/projectcalico/typha/pkg/syncproto"
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
)

type SyncServerContextKey string

const CxtKeyConnID = SyncServerContextKey("ConnID")

type SyncServer struct {
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
}

func New(cache BreadcrumbProvider, config Config) *SyncServer {
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

	return &SyncServer{
		config: config,
		cache:  cache,
	}
}

func (s *SyncServer) Serve(cxt context.Context) {
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
		connCxt := context.WithValue(cxt, CxtKeyConnID, connID)
		go s.handleConnection(connCxt, conn)
	}
}

// handleConnection is a goroutine that handles a single connection from a client.
func (s *SyncServer) handleConnection(connCxt context.Context, conn *net.TCPConn) error {
	connLogCxt := log.WithFields(log.Fields{
		"client": conn.RemoteAddr(),
		"connID": connCxt.Value(CxtKeyConnID),
	})
	logCxt := connLogCxt.WithFields(log.Fields{
		"thread": "conn",
	})
	logCxt.Info("Per-connection goroutine started")

	// Create a new connection-scoped context, which we'll use for signaling to our child
	// goroutines to halt.
	connCxt, cancel := context.WithCancel(connCxt)
	shutDownWG := &sync.WaitGroup{}
	gaugeNumConnections.Inc()
	defer func() {
		// Cancel the context and close the connection, this will trigger our background
		// threads to shut down.
		cancel()
		conn.Close()
		// Wait for the background threads to shut down.
		shutDownWG.Wait()
		gaugeNumConnections.Dec()
		logCxt.Info("Client connection shut down.")
	}()

	r := gob.NewDecoder(conn)
	rC := make(chan interface{})

	// Start goroutine to read messages from client and put them on a channel for this
	// goroutine to process.
	shutDownWG.Add(1)
	go func() {
		logCxt := connLogCxt.WithField("thread", "read")
		defer func() {
			cancel()
			close(rC)
			shutDownWG.Done()
			logCxt.Info("Read goroutine finished")
		}()
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
			case rC <- envelope.Message:
			case <-connCxt.Done():
				return
			}

		}
	}()

	{
		// Read the hello message from the client.
		helloTimeout := time.NewTimer(60 * time.Second)
		select {
		case clientHello := <-rC:
			if clientHello == nil {
				logCxt.Warning("Failed to read hello from client")
				return errors.New("Failed to read hello from client")
			}
			logCxt.WithField("msg", clientHello).Info("Received hello from client.")
			helloTimeout.Stop()
		case <-helloTimeout.C:
			logCxt.Warning("Timed out waiting for hello from client")
			return errors.New("Timed out waiting for hello from client")
		}
	}

	// Create an Encoder to write our messages to the client.  The Encoder is thread-safe so
	// we can send pings and KVs from separate goroutines.
	w := gob.NewEncoder(conn)
	sendMsg := func(msg interface{}) error {
		if connCxt.Err() != nil {
			// Optimisation, don't bother to send if we're being torn down.
			return connCxt.Err()
		}
		envelope := syncproto.Envelope{
			Message: msg,
		}
		startTime := time.Now()
		err := w.Encode(&envelope)
		if err != nil {
			logCxt.WithError(err).Info("Failed to write to client")
			return err
		}
		summaryWriteLatency.Observe(time.Since(startTime).Seconds())
		return nil
	}

	// Respond to client's hello.
	err := sendMsg(syncproto.MsgServerHello{
		Version: buildinfo.GitVersion,
	})
	if err != nil {
		log.WithError(err).Warning("Failed to send hello to client")
		return err
	}

	// Start a goroutine to stream the snapshot and then the deltas to the client.
	shutDownWG.Add(1)
	go func() {
		logCxt := connLogCxt.WithField("thread", "kv-sender")
		defer func() {
			cancel()
			shutDownWG.Done()
			logCxt.Info("KV-sender goroutine finished")
		}()

		// Get the current snapshot and stream it to the client...
		breadcrumb := s.cache.CurrentBreadcrumb()
		logCxt.WithFields(log.Fields{
			"seqNo":  breadcrumb.SequenceNumber,
			"status": breadcrumb.SyncStatus,
		}).Info("Starting to send snapshot to client")
		cancelC := make(chan struct{})
		iter := breadcrumb.KVs.Iterator(cancelC)

		var kvs []syncproto.SerializedUpdate
	snapLoop:
		for {
			select {
			case <-connCxt.Done():
				logCxt.Info("Asked to stop by Context")
				close(cancelC)
				return
			case entry := <-iter:
				if len(kvs) >= s.config.MaxMessageSize || (len(kvs) > 0 && entry == nil) {
					logCxt.WithField("numKVs", len(kvs)).Debug("Sending snapshot KVs to client.")
					summaryNumKVsPerMsg.Observe(float64(len(kvs)))
					err := sendMsg(syncproto.MsgKVs{
						KVs: kvs,
					})
					if err != nil {
						close(cancelC)
						logCxt.WithError(err).Info("Failed to send to client")
						return
					}
					kvs = kvs[:0]
				}
				if entry == nil {
					close(cancelC)
					break snapLoop
				}
				kvs = append(kvs, entry.Value.(syncproto.SerializedUpdate))
			}
		}

		var lastSentStatus api.SyncStatus
		for connCxt.Err() == nil {
			if lastSentStatus != breadcrumb.SyncStatus {
				logCxt.WithField("newStatus", breadcrumb.SyncStatus).Info(
					"Status update to send.")
				err := sendMsg(syncproto.MsgSyncStatus{
					SyncStatus: breadcrumb.SyncStatus,
				})
				if err != nil {
					logCxt.WithError(err).Info(
						"Failed to send status to client")
					return
				}
				lastSentStatus = breadcrumb.SyncStatus
			}

			// Wait for new Breadcrumbs.  If we're behind, we may coalesce the deltas
			// from multiple Breadcrumbs before exiting the loop.
			var deltas []syncproto.SerializedUpdate
			for len(deltas) < s.config.MaxMessageSize {
				nextStartTime := time.Now()
				breadcrumb, err = breadcrumb.Next(connCxt)
				if err != nil {
					logCxt.WithError(err).Error(
						"Getting next Breadcrumb canceled")
					return
				}
				timeSpentInNext := time.Since(nextStartTime)
				logCxt.WithFields(log.Fields{
					"seqNo":     breadcrumb.SequenceNumber,
					"timestamp": breadcrumb.Timestamp,
				}).Debug("New snapshot")

				latestCrumb := s.cache.CurrentBreadcrumb()
				mySnapAge := latestCrumb.Timestamp.Sub(breadcrumb.Timestamp)

				// Check if we're too far behind the latest snapshot.
				summaryClientLatency.Observe(mySnapAge.Seconds())
				if mySnapAge > s.config.MaxFallBehind {
					logCxt.WithFields(log.Fields{
						"snapAge":     mySnapAge,
						"mySeqNo":     breadcrumb.SequenceNumber,
						"latestSeqNo": latestCrumb.SequenceNumber,
					}).Warn("Client fell behind. Disconnecting.")
					return
				}

				if mySnapAge > s.config.MinBatchingAgeThreshold || deltas != nil {
					// We're behind (or already batching) need to append the
					// deltas.
					deltas = append(deltas, breadcrumb.Updates...)
					summaryNextCatchupLatency.Observe(timeSpentInNext.Seconds())
				}
				if mySnapAge > s.config.MinBatchingAgeThreshold {
					// Still behind, batch if we can.
					continue
				}
				if deltas == nil {
					// Optimisation, this is the first and only batch, avoid
					// copying the deltas.
					deltas = breadcrumb.Updates
				}
				break
			}

			if len(deltas) == 0 {
				logCxt.Debug("Breadcrumb contained no deltas. Skipping sending updates to client.")
				continue
			}

			// Send the deltas relative to the previous snapshot.
			summaryNumKVsPerMsg.Observe(float64(len(deltas)))
			err := sendMsg(syncproto.MsgKVs{
				KVs: deltas,
			})
			if err != nil {
				logCxt.WithError(err).Info("Failed to send to client.")
				return
			}
		}
	}()

	// Start a ticker to trigger periodic pings.  We send pings from their own goroutine so
	// that, if the Encoder blocks, we don't prevent the main goroutine from checking the
	// timer.
	pingTicker := jitter.NewTicker(10*time.Second, 1*time.Second)
	defer pingTicker.Stop()

	shutDownWG.Add(1)
	go func() {
		logCxt := connLogCxt.WithField("thread", "pinger")
		defer func() {
			cancel()
			shutDownWG.Done()
			logCxt.Info("Pinger goroutine shut down.")
		}()
		for {
			select {
			case <-pingTicker.C:
			case <-connCxt.Done():
				log.WithError(err).Info("Context was canceled.")
				return
			}
			logCxt.Debug("Sending ping.")
			err := sendMsg(syncproto.MsgPing{
				Timestamp: time.Now(),
			})
			if err != nil {
				log.WithError(err).Info("Failed to send ping to client")
				return
			}
		}
	}()

	// Start a ticker to check that we receive pongs in a timely fashion.
	pongTicker := jitter.NewTicker(10*time.Second, 1*time.Second)
	defer pongTicker.Stop()
	lastPongReceived := time.Now()

	logCxt.Info("Waiting for messages from client")
	for {
		select {
		case msg := <-rC:
			if msg == nil {
				logCxt.Info("Read channel ended")
				return connCxt.Err()
			}
			switch msg := msg.(type) {
			case syncproto.MsgPong:
				logCxt.Debug("Pong from client")
				lastPongReceived = time.Now()
				summaryPingLatency.Observe(time.Since(msg.PingTimestamp).Seconds())
			default:
				logCxt.WithField("msg", msg).Error("Unknown message from client")
				return errors.New("Unknown message type")
			}
		case <-pongTicker.C:
			if time.Since(lastPongReceived) > 60*time.Second {
				logCxt.Info("Too long since last pong from client, disconnecting")
				return errors.New("No pong received from client")
			}
		case <-connCxt.Done():
			logCxt.Info("Asked to stop by Context.")
			return connCxt.Err()
		}
	}
}
