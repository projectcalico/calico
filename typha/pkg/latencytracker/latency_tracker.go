package latencytracker

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

type LatencyTracker struct {
	lock       sync.Mutex
	clients    map[uint64]*ClientTracker
	crumbs     map[uint64]time.Time // Maps breadcrumb sequence number to creation time
	syncerType syncproto.SyncerType
	serverID   string
}

func New(syncerType syncproto.SyncerType, myServerID string) *LatencyTracker {
	return &LatencyTracker{
		clients:    make(map[uint64]*ClientTracker),
		crumbs:     make(map[uint64]time.Time),
		syncerType: syncerType,
		serverID:   myServerID,
	}
}

func (l *LatencyTracker) RegisterClient(connID uint64, address string) *ClientTracker {
	l.lock.Lock()
	defer l.lock.Unlock()

	logrus.Infof("Registering client %d at %s for syncer type %s", connID, address, l.syncerType)

	c := &ClientTracker{
		latencyTracker: l,
		connID:         connID,
		address:        address,
		creationTime:   time.Now(),
	}
	l.clients[connID] = c
	return c
}

func (l *LatencyTracker) RecordBreadcrumbCreation(rev model.TyphaRevision) {
	l.lock.Lock()
	defer l.lock.Unlock()

	seqNo, err := strconv.ParseUint(rev.Revision, 10, 64)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to parse revision from %s", rev)
		return
	}
	l.crumbs[seqNo] = rev.Timestamp
}

func (l *LatencyTracker) recordClientClose(id uint64) {
	l.lock.Lock()
	defer l.lock.Unlock()

	delete(l.clients, id)
}

func (l *LatencyTracker) Start(ctx context.Context) {
	go l.loop(ctx)
}

func (l *LatencyTracker) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
			l.ReportLatencies()
		}
	}
}

func (l *LatencyTracker) ReportLatencies() {
	l.lock.Lock()
	defer l.lock.Unlock()

	const maxPower = 6                   // We will use log10 of latency in milliseconds, capped at 10
	histogram := make([]int, maxPower+1) // Buckets for log10 of latency in milliseconds (0-10)
	noReports := 0
	missingCrumb := 0
	var minCrumb uint64 = math.MaxUint64
	maxBucketUsed := -1
	for _, c := range l.clients {
		lastUpdate := c.lastUpdate.Load()
		if lastUpdate == nil {
			noReports++
			minCrumb = 0
			continue
		}
		crumbCreationTime := l.crumbs[lastUpdate.breadcrumbSeqNo]
		if crumbCreationTime.IsZero() {
			missingCrumb++
			minCrumb = 0
			continue
		}
		if crumbCreationTime.Before(c.creationTime) {
			// If the crumb was created before the client was registered,
			// use the client's creation time.
			crumbCreationTime = c.creationTime
		}
		latency := lastUpdate.timestamp.Sub(crumbCreationTime)
		if latency < 0 {
			latency = 0
		}
		if lastUpdate.breadcrumbSeqNo < minCrumb {
			minCrumb = lastUpdate.breadcrumbSeqNo
		}

		log10Millis := math.Log10(latency.Seconds() * 1000)
		if log10Millis < 0 {
			log10Millis = 0
		}
		log10Millis = math.Min(log10Millis, maxPower)
		bucket := int(log10Millis) // Convert to bucket index
		histogram[bucket] = histogram[bucket] + 1
		if bucket > maxBucketUsed {
			maxBucketUsed = bucket
		}
	}

	output := fmt.Sprintf("Latency Report %v:", l.syncerType)
	for i, count := range histogram {
		if i > maxBucketUsed {
			break
		}
		// Output each bucket's range in milliseconds, e.g., 0-10ms, 10-100ms, etc.
		lowerBound := int(math.Pow(10, float64(i-1)))
		upperBound := int(math.Pow(10, float64(i)))
		if i == maxPower {
			output += fmt.Sprintf("\n%d+ms-∞: ", lowerBound)
		} else {
			output += fmt.Sprintf("\n%d-%dms: ", lowerBound, upperBound)
		}
		output += fmt.Sprintf("%d clients", count)
	}
	if noReports > 0 {
		output += fmt.Sprintf("\nNo report (yet): %d clients", noReports)
	}
	if missingCrumb > 0 {
		output += fmt.Sprintf("\nMissing crumb: %d clients", missingCrumb)
	}
	logrus.Info(output)

	// Make sure we don't leak crumbs forever.
	for crumbSeqNo, creationTime := range l.crumbs {
		if time.Since(creationTime) > 10*time.Minute && crumbSeqNo < minCrumb {
			delete(l.crumbs, crumbSeqNo)
		}
	}
}

type ClientTracker struct {
	latencyTracker *LatencyTracker

	connID       uint64
	address      string
	creationTime time.Time

	lastUpdate atomic.Pointer[update]
}

type update struct {
	breadcrumbSeqNo uint64
	timestamp       time.Time
}

func (c *ClientTracker) RecordDataplaneUpdate(msg syncproto.MsgDataplaneRevision) {
	if msg.ServerID != c.latencyTracker.serverID {
		// Can happen when a client reconnects.
		logrus.Debugf("Received update for different server ID %s, expected %s", msg.ServerID, c.latencyTracker.serverID)
		return
	}
	seqNo, err := strconv.ParseUint(msg.Revision, 10, 64)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to parse revision from %s", msg)
		return
	}

	c.lastUpdate.Store(&update{
		breadcrumbSeqNo: seqNo,
		timestamp:       msg.Timestamp,
	})
}

func (c *ClientTracker) Close() {
	c.latencyTracker.recordClientClose(c.connID)
}
