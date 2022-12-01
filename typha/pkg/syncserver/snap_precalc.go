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
	"os"
	"sync"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/promutils"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
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

type SnappySnapshotCache struct {
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

	writeTimeout time.Duration
}

func NewSnappySnapCache(
	syncerName string,
	cache BreadcrumbProvider,
	snapValidityTimeout time.Duration,
	writeTimeout time.Duration,
) *SnappySnapshotCache {
	s := &SnappySnapshotCache{
		snapValidityTimeout: snapValidityTimeout,
		writeTimeout:        writeTimeout,
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
func (s *SnappySnapshotCache) SendSnapshot(ctx context.Context, w io.Writer, conn WriteDeadlineSetter) (*snapcache.Breadcrumb, error) {
	// activeBinarySnapshot ensures there is an active snapshot and returns it.  The snapshot may or may not
	// be complete yet.
	snap := s.activeBinarySnapshot()
	if err := snap.sendToClient(ctx, s.logCtx, w, conn, s.writeTimeout); err != nil {
		return nil, err
	}
	return snap.crumb, nil
}

type WriteDeadlineSetter interface {
	SetWriteDeadline(newDeadline time.Time) error
}

// activeBinarySnapshot either returns the current active snapshot (which may still be being created on a background
// goroutine), or it starts a new snapshot.  The returned snapshot's complete flag will be set once it is finished.
func (s *SnappySnapshotCache) activeBinarySnapshot() *snapshot {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.activeSnapshot == nil {
		breadcrumb := s.cache.CurrentBreadcrumb()
		s.activeSnapshot = &snapshot{
			cond:  sync.NewCond(&s.lock),
			lock:  &s.lock,
			crumb: breadcrumb,
		}
		go s.populateSnapshot(s.activeSnapshot)
	} else {
		s.counterBinSnapsReused.Inc()
	}
	return s.activeSnapshot
}

func (s *SnappySnapshotCache) populateSnapshot(snap *snapshot) {
	s.writeDataToSnapshot(snap)
	// Wait until the snapshot expires...
	time.Sleep(s.snapValidityTimeout)
	// No point in expiring the snapshot until there's a new one...
	_, _ = snap.crumb.Next(context.Background())
	s.clearSnapshot()
}

func (s *SnappySnapshotCache) clearSnapshot() {
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

func (s *SnappySnapshotCache) writeDataToSnapshot(snap *snapshot) {
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
	crumb *snapcache.Breadcrumb

	cond *sync.Cond
	lock *sync.Mutex

	buf      []byte
	complete bool
}

func (s *snapshot) sendToClient(ctx context.Context, logCtx *logrus.Entry, w io.Writer, conn WriteDeadlineSetter, writeTimeout time.Duration) error {
	var bytesSent int
	var currentWriteDeadline time.Time

	complete := false
	for ctx.Err() == nil && !complete {
		var buf []byte
		buf, complete = s.waitForData(ctx, bytesSent)

		for len(buf) > 0 {
			if ctx.Err() != nil {
				logCtx.Info("Context finished, aborting send of snapshot.")
				return ctx.Err()
			}

			// Optimisation: only reset the deadline if we've used a significant portion of it.
			// Setting it seems to be fairly expensive.
			if time.Until(currentWriteDeadline) < writeTimeout {
				newDeadline := time.Now().Add(writeTimeout * 110 / 100)
				err := conn.SetWriteDeadline(newDeadline)
				if err != nil {
					return err
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
				return err
			}
		}
	}

	// Unset the timeout; under normal operation, we rely on a regular round tripped ping/pong message instead.
	var zeroTime time.Time
	err := conn.SetWriteDeadline(zeroTime)
	if err != nil {
		return err
	}

	return nil
}

func (s *snapshot) waitForData(ctx context.Context, bytesAlreadySent int) (buf []byte, complete bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for len(s.buf) == bytesAlreadySent && ctx.Err() == nil {
		s.cond.Wait()
	}
	buf = s.buf[bytesAlreadySent:]
	complete = s.complete
	return
}
