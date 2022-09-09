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
	"bytes"
	"context"
	"encoding/gob"
	"net"
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

type Snapshotter struct {
	snapValidityTimeout time.Duration

	cache BreadcrumbProvider

	lock           sync.Mutex
	cond           sync.Cond
	activeSnapshot *snapshot

	counterBinSnapsGenerated prometheus.Counter
	counterBinSnapsReused    prometheus.Counter
	gaugeSnapBytesRaw        prometheus.Gauge
	gaugeSnapBytesComp       prometheus.Gauge
}

func NewSnapshotter(syncerName string, snapValidityTimeout time.Duration, cache BreadcrumbProvider) *Snapshotter {
	s := &Snapshotter{
		snapValidityTimeout: snapValidityTimeout,
		cache:               cache,

		counterBinSnapsGenerated: counterVecSnapshotsGenerated.WithLabelValues(syncerName),
		counterBinSnapsReused:    counterVecSnapshotsReused.WithLabelValues(syncerName),
		gaugeSnapBytesRaw:        gaugeVecSnapRawBytes.WithLabelValues(syncerName),
		gaugeSnapBytesComp:       gaugeVecSnapCompressedBytes.WithLabelValues(syncerName),
	}
	s.cond.L = &s.lock
	return s
}

func (s *Snapshotter) SendSnapshot(ctx context.Context, w net.Conn) (*snapcache.Breadcrumb, error) {
	snap, err := s.getOrWaitForSnap(ctx)
	if err != nil {
		return nil, err
	}
	buf := snap.buf
	for len(buf) > 0 {
		const chunkSize = 65536
		b := buf
		if len(b) > chunkSize {
			b = b[:chunkSize]
		}
		err = w.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if err != nil {
			return nil, err
		}
		n, err := w.Write(b)
		if err != nil {
			return nil, err
		}
		buf = buf[n:]
	}
	var zeroTime time.Time
	err = w.SetWriteDeadline(zeroTime)
	if err != nil {
		return nil, err
	}
	return snap.crumb, nil
}

func (s *Snapshotter) getOrWaitForSnap(ctx context.Context) (*snapshot, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.activeSnapshot == nil {
		s.activeSnapshot = &snapshot{
			crumb: s.cache.CurrentBreadcrumb(),
		}
		go s.populateSnapshot(s.activeSnapshot)
	} else {
		s.counterBinSnapsReused.Inc()
	}
	// Lock in the snapshot that we're waiting for by takin ga local copy.  Otherwise, we might miss our snapshot
	// (due to racing with a fresh call to getOrWaitForSnap()) and end up waiting for the next one.
	snap := s.activeSnapshot
	for !snap.done {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.cond.Wait()
	}
	return snap, nil
}

func (s *Snapshotter) populateSnapshot(snap *snapshot) {
	buf := s.writeSnapshotToBuffer(snap)
	s.publishSnapshot(snap, buf)
	// Wait until the snapshot expires...
	time.Sleep(s.snapValidityTimeout)
	// No point in expiring the snapshot until there's a new one...
	_, _ = snap.crumb.Next(context.Background())
	s.clearSnapshot()
}

func (s *Snapshotter) clearSnapshot() {
	s.lock.Lock()
	s.activeSnapshot = nil
	s.lock.Unlock()
}

func (s *Snapshotter) publishSnapshot(snap *snapshot, buf bytes.Buffer) {
	s.lock.Lock()
	snap.buf = buf.Bytes()
	snap.done = true
	s.cond.Broadcast()
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

func (s *Snapshotter) writeSnapshotToBuffer(snap *snapshot) bytes.Buffer {
	s.counterBinSnapsGenerated.Inc()
	var buf bytes.Buffer
	snappyW := snappy.NewBufferedWriter(&buf)
	progressW := progressWriter{W: snappyW}
	encoder := gob.NewEncoder(&progressW)
	writeMsg := func(msg any) error {
		envelope := syncproto.Envelope{
			Message: msg,
		}
		err := encoder.Encode(&envelope)
		if err != nil {
			return err
		}
		return nil
	}
	err := writeSnapshotMessages(context.Background(), logrus.WithField("thread", "snapshotter"), snap.crumb, writeMsg, 100)
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		logrus.WithError(err).Panic("Failed to serialise datastore snapshot.")
	}

	err = writeMsg(syncproto.MsgDecoderRestart{
		Message:              "End of compressed snapshot.",
		CompressionAlgorithm: syncproto.CompressionSnappy,
	})
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		logrus.WithError(err).Panic("Failed to serialise datastore snapshot end message.")
	}

	err = snappyW.Close() // Does Flush() for us.
	if err != nil {
		// Shouldn't happen because we're serialising to an in-memory buffer.
		logrus.WithError(err).Panic("Failed to close datastore snapshot.")
	}
	s.gaugeSnapBytesRaw.Set(float64(progressW.BytesWritten))
	s.gaugeSnapBytesComp.Set(float64(buf.Len()))
	return buf
}

type snapshot struct {
	crumb *snapcache.Breadcrumb
	buf   []byte
	done  bool
}

// writeSnapshotMessages chunks the given breadcrumb up into syncproto.MsgKVs objects and calls writeMsg for each one.
func writeSnapshotMessages(ctx context.Context, logCxt *logrus.Entry, breadcrumb *snapcache.Breadcrumb, writeMsg func(any) error, maxMsgSize int) (err error) {
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
		// h.summaryNumKVsPerMsg.Observe(float64(len(kvs))) FIXME stats for snapshot
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
	return
}
