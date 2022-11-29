// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package syncserver

import (
	"context"
	"encoding/gob"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/projectcalico/calico/typha/pkg/promutils"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	counterVecSnapshotsGenerated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_snapshot_generated",
		Help: "Number of binary snapshots generated.",
	}, []string{"syncer"})
	counterVecSnapshotsReused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_snapshot_reused",
		Help: "Number of binary snapshots that were cached and reused.",
	}, []string{"syncer"})
	gaugeVecSnapRawBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_snapshot_raw_bytes",
		Help: "Size of the most recently generated binary snapshot (before compression).",
	}, []string{"syncer"})
	gaugeVecSnapCompressedBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_snapshot_compressed_bytes",
		Help: "Size of the most recently generated binary snapshot (after compression).",
	}, []string{"syncer"})
)

func init() {
	promutils.PreCreateCounterPerSyncer(counterVecSnapshotsGenerated)
	prometheus.MustRegister(counterVecSnapshotsGenerated)
	promutils.PreCreateCounterPerSyncer(counterVecSnapshotsReused)
	prometheus.MustRegister(counterVecSnapshotsReused)
	promutils.PreCreateGaugePerSyncer(gaugeVecSnapRawBytes)
	prometheus.MustRegister(gaugeVecSnapRawBytes)
	promutils.PreCreateGaugePerSyncer(gaugeVecSnapCompressedBytes)
	prometheus.MustRegister(gaugeVecSnapCompressedBytes)
}

type BinarySnapshotCache struct {
	snapValidityTimeout time.Duration
	logCtx              *logrus.Entry

	cache BreadcrumbProvider

	lock           sync.Mutex
	cond           sync.Cond
	activeSnapshot *snapshot

	counterBinSnapsGenerated prometheus.Counter
	counterBinSnapsReused    prometheus.Counter
	gaugeSnapBytesRaw        prometheus.Gauge
	gaugeSnapBytesComp       prometheus.Gauge
}

func NewBinarySnapCache(
	syncerName string,
	cache BreadcrumbProvider,
	snapValidityTimeout time.Duration,
) *BinarySnapshotCache {
	s := &BinarySnapshotCache{
		snapValidityTimeout: snapValidityTimeout,
		cache:               cache,
		logCtx: logrus.WithFields(logrus.Fields{
			"thread": "snapshotter",
			"syncer": syncerName,
		}),
		counterBinSnapsGenerated: counterVecSnapshotsGenerated.WithLabelValues(syncerName),
		counterBinSnapsReused:    counterVecSnapshotsReused.WithLabelValues(syncerName),
		gaugeSnapBytesRaw:        gaugeVecSnapRawBytes.WithLabelValues(syncerName),
		gaugeSnapBytesComp:       gaugeVecSnapCompressedBytes.WithLabelValues(syncerName),
	}
	s.cond.L = &s.lock
	return s
}

// SendSnapshot waits for a binary snapshot to be ready and then sends it as a raw snappy-compressed gob stream
// on the given connection.  Since the stream is cached, it starts with fresh snappy/gob headers.  Hence, the
// decoder at the client side must also be reset before sending such a snapshot.  The snapshot ends with
// a MsgDecoderRestart, so the caller should wait for an ACK and then reset their encoder.
func (s *BinarySnapshotCache) SendSnapshot(ctx context.Context, w io.Writer, conn net.Conn) (*snapcache.Breadcrumb, error) {
	snap := s.getOrCreateSnap()

	s.lock.Lock()

	var bytesSent int
	var currentWriteDeadline time.Time
	for bytesSent < len(snap.buf) || !snap.complete {
		for len(snap.buf) == bytesSent && ctx.Err() == nil {
			snap.cond.Wait()
		}
		buf := snap.buf[bytesSent:]
		complete := snap.complete

		// Drop the lock while we send the data.
		s.lock.Unlock()

		for len(buf) > 0 {
			if ctx.Err() != nil {
				s.logCtx.Info("Context finished, aborting send of snapshot.")
				return nil, ctx.Err()
			}
			if time.Until(currentWriteDeadline) < 60*time.Second {
				newDeadline := time.Now().Add(90 * time.Second)
				err := conn.SetWriteDeadline(newDeadline)
				if err != nil {
					return nil, err
				}
				currentWriteDeadline = newDeadline
			}
			n, err := w.Write(buf)
			buf = buf[n:]
			bytesSent += n
			if err != nil {
				if n > 0 && os.IsTimeout(err) {
					// Managed to write _some_ bytes, loop again to reset the timeout.  If the snapshot was
					// very large then we might have written a big chunk of it but simply not had enough time to
					// complete.  Only give up if we see no progress at all.
					continue
				}
				return nil, err
			}
		}

		if complete {
			break
		}
		s.lock.Lock()
	}

	// Unset the timeout; under normal operation, we rely on a regular round tripped ping/pong message instead.
	var zeroTime time.Time
	err := conn.SetWriteDeadline(zeroTime)
	if err != nil {
		return nil, err
	}
	return snap.crumb, nil
}

// getOrCreateSnap either returns the current active snapshot (which may still be being created on a background
// goroutine), or it starts a new snapshot.  The returned snapshot's done channel will be closed once it is ready
// and it is guaranteed to become ready at some point.
func (s *BinarySnapshotCache) getOrCreateSnap() *snapshot {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.activeSnapshot == nil {
		s.activeSnapshot = &snapshot{
			cond:  sync.NewCond(&s.lock),
			crumb: s.cache.CurrentBreadcrumb(),
		}
		go s.populateSnapshot(s.activeSnapshot)
	} else {
		s.counterBinSnapsReused.Inc()
	}
	return s.activeSnapshot
}

func (s *BinarySnapshotCache) populateSnapshot(snap *snapshot) {
	s.writeSnapshot(snap)
	// Wait until the snapshot expires...
	time.Sleep(s.snapValidityTimeout)
	// No point in expiring the snapshot until there's a new one...
	_, _ = snap.crumb.Next(context.Background())
	s.clearSnapshot()
}

func (s *BinarySnapshotCache) clearSnapshot() {
	s.lock.Lock()
	s.activeSnapshot = nil
	s.lock.Unlock()
}

type progressWriter struct {
	W            *snappy.Writer
	BytesWritten int
}

func (p2 *progressWriter) Write(p []byte) (n int, err error) {
	n, err = p2.W.Write(p)
	p2.BytesWritten += n
	return
}

type appendOnlyByteBuffer struct {
	Buf []byte
}

func (a *appendOnlyByteBuffer) Write(p []byte) (n int, err error) {
	a.Buf = append(a.Buf, p...)
	return len(p), nil
}

func (a *appendOnlyByteBuffer) Len() int {
	return len(a.Buf)
}

var _ io.Writer = (*appendOnlyByteBuffer)(nil)

func (s *BinarySnapshotCache) writeSnapshot(snap *snapshot) {
	s.counterBinSnapsGenerated.Inc()
	var buf appendOnlyByteBuffer

	snappyW := snappy.NewBufferedWriter(&buf)
	progressW := progressWriter{W: snappyW}
	encoder := gob.NewEncoder(&progressW)
	lastFlushTime := time.Now()
	writeMsg := func(msg any) error {
		envelope := syncproto.Envelope{
			Message: msg,
		}
		err := encoder.Encode(&envelope)
		if err != nil {
			return err
		}

		if time.Since(lastFlushTime) > 20*time.Millisecond {
			lastFlushTime = time.Now()
			err = snappyW.Flush()
			if err != nil {
				return err
			}
			s.lock.Lock()
			snap.buf = buf.Buf
			// Using Signal() instead of Broadcast() so that we only wake up one waiter at a time.  That avoids
			// having a thundering herd of wake-ups, which then starve out this goroutine so that they all block
			// again, then we wake them all up again. Doing it this way we'll wake them up less frequently but
			// they'll get to write more data in one shot.
			snap.cond.Signal()
			s.lock.Unlock()
		}
		return nil
	}
	err := writeSnapshotMessages(
		context.Background(),
		s.logCtx.WithField("destination", "compressed in-memory cache"),
		snap.crumb,
		writeMsg,
		1000, // Allow bigger messages in the snapshot.
	)
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		s.logCtx.WithError(err).Panic("Failed to serialise datastore snapshot.")
	}

	err = writeMsg(syncproto.MsgDecoderRestart{
		Message:              "End of compressed snapshot.",
		CompressionAlgorithm: syncproto.CompressionSnappy,
	})
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		s.logCtx.WithError(err).Panic("Failed to serialise datastore snapshot end message.")
	}

	err = snappyW.Close() // Does Flush() for us.
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		s.logCtx.WithError(err).Panic("Failed to close datastore snapshot.")
	}

	// One final flush/broadcast to wake up all our waiters.
	s.lock.Lock()
	snap.buf = buf.Buf
	snap.complete = true
	snap.cond.Broadcast()
	s.lock.Unlock()

	s.gaugeSnapBytesRaw.Set(float64(progressW.BytesWritten))
	s.gaugeSnapBytesComp.Set(float64(buf.Len()))
}

type snapshot struct {
	crumb    *snapcache.Breadcrumb
	buf      []byte
	cond     *sync.Cond
	complete bool
}

// writeSnapshotMessages chunks the given breadcrumb up into syncproto.MsgKVs objects and calls writeMsg for each one.
func writeSnapshotMessages(
	ctx context.Context,
	logCxt *logrus.Entry,
	breadcrumb *snapcache.Breadcrumb,
	writeMsg func(any) error,
	maxMsgSize int,
) (err error) {
	logCxt = logCxt.WithFields(logrus.Fields{
		"seqNo":  breadcrumb.SequenceNumber,
		"status": breadcrumb.SyncStatus,
	})
	logCxt.Info("Starting to write snapshot")

	// writeKVs is a utility function that sends the kvs buffer to the client (if non-empty) and clears the buffer.
	var kvs []syncproto.SerializedUpdate
	var numKeys int
	writeKVs := func() error {
		if len(kvs) == 0 {
			return nil
		}
		logCxt.WithField("numKVs", len(kvs)).Debug("Writing snapshot KVs.")
		numKeys += len(kvs)
		err := writeMsg(syncproto.MsgKVs{
			KVs: kvs,
		})
		if err != nil {
			logCxt.WithError(err).Info("Failed to write snapshot KVs")
		}
		kvs = kvs[:0]
		return err
	}

	breadcrumb.KVs.Ascend(func(entry syncproto.SerializedUpdate) bool {
		if ctx.Err() != nil {
			err = ctx.Err()
			return false
		}
		kvs = append(kvs, entry)
		if len(kvs) >= maxMsgSize {
			// Buffer is full, send the next batch.
			err = writeKVs()
			if err != nil {
				return false
			}
		}
		return true
	})
	if err != nil {
		return
	}

	err = writeKVs()
	if err != nil {
		return
	}
	logCxt.Info("Finished writing snapshot.")
	return
}
