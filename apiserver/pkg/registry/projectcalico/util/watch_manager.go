package util

import (
	"context"
	"sync"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

type WatchRecord struct {
	ID    string
	Kind  string
	Watch watch.Interface
	Ctx   context.Context
}

// WatchManager is used for managing watches for policies. Due to the policy tiers implementation and RBAC we are not able to update the watch on the go.
// This causes that established watch might miss out on events if a new Tier has been created after the watch has been established and the user has access to that Tier.
// WatchManager ensures that in an even of new Tier being added all watches are canceled and the consumer will reestablish watch receiving events from the newly added tier
// This is true for all policies - NetworkPolicy, GlobalNetworkPolicy, StagedNetworkPolicy, StagedGlobalNetworkPolicy
type WatchManager struct {
	client       api.Client
	syncer       api.Syncer
	sync         chan struct{}
	watchRecords sync.Map
}

func NewWatchManager(cc api.Client) *WatchManager {
	return &WatchManager{
		client:       cc,
		sync:         make(chan struct{}),
		watchRecords: sync.Map{},
	}
}

func (m *WatchManager) Start() {
	m.syncer = watchersyncer.New(
		m.client,
		[]watchersyncer.ResourceType{
			{ListInterface: model.ResourceListOptions{Kind: v3.KindTier}},
		},
		m,
	)
	m.syncer.Start()
}

func (m *WatchManager) WaitForCacheSync(stopCh <-chan struct{}) {
	select {
	case <-m.sync:
	case <-stopCh:
	}
}

func (m *WatchManager) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		close(m.sync)
	}
}

func (m *WatchManager) OnUpdates(updates []api.Update) {
	for _, u := range updates {
		// We do not need to cancel watches for delete as the original watch is still valid with other records
		if u.Key.(model.ResourceKey).Kind == v3.KindTier && u.Value != nil {
			// New Tier added, we need to stop all watches in case there is a user that can watch policies in the new Tier
			// When the watch is re-established it will contain policies in the newly created Tier
			logrus.WithField("Tier", u.Key.(model.ResourceKey).Name).Debug("New Tier added, removing all WatchRecords")
			m.watchRecords.Range(func(k, v interface{}) bool {
				id, ok := k.(string)
				if !ok {
					logrus.WithField("id", k).Warn("ID is not a string")
					return true
				}
				record, ok := v.(WatchRecord)
				if !ok {
					logrus.WithField("id", id).Errorf("Value is not a WatchRecord")
					return true
				}
				logrus.WithFields(logrus.Fields{"id": record.ID, "Kind": record.Kind}).Debug("Closing watch")
				record.Watch.Stop()
				return true
			})
			m.watchRecords = sync.Map{}
		}
	}
}

// AddWatch adds a watch to our map and triggers monitoring for watch closure by the consumer or API server
func (m *WatchManager) AddWatch(record WatchRecord) {
	logrus.WithFields(logrus.Fields{"id": record.ID, "Kind": record.Kind}).Debug("Adding WatchRecord")
	m.watchRecords.Store(record.ID, record)
	go m.monitorWatch(record)
}

// monitorWatch waits to see if the context is done signaling that the watch has been ended. We can remove the watch from our map
func (m *WatchManager) monitorWatch(record WatchRecord) {
	<-record.Ctx.Done()
	// Watch has been closed, we should remove it from our map
	logrus.WithFields(logrus.Fields{"id": record.ID, "Kind": record.Kind}).Debug("Watch has been stopped, removing WatchRecord")
	m.watchRecords.Delete(record.ID)
}
