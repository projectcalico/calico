package networkpolicy

import (
	"context"
	"os"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

// NewMigratorController creates a new controller that migrates network policies
// from v1 names to v3 names in the datastore.
//
// In Calico v3.32, the naming convention for network policies was changed to remove the tier prefixing requirement.
// As part of this, we aligned the v3 object names with the actual datastore (crd.projectcalico.org/v1 and etcdv3) object names
// for newly created policies. However, existing policies created prior to v3.32 retained their original v1 names in the datastore.
// This controller is responsible for migrating those existing policies to use the new v3 naming convention in the datastore for consistency.
//
// Note: This controller only migrates policies in the "default" tier, as policies in other tiers have always had validation that prevents
// the naming mismatch.
//
// The migration process involves:
//  1. Listing all network policies in the datastore.
//  2. Identifying policies where the v1 name (in the datastore Key) differs from the v3 name (in the ObjectMeta).
//  3. For each mismatched policy:
//     a. Create a new policy entry in the datastore with the correct v3 name.
//     b. Delete the old policy entry with the v1 name.
func NewMigratorController(ctx context.Context, cs kubernetes.Interface, cli clientv3.Interface, feed *utils.DataFeed) controller.Controller {
	// Read the namespace from the service account file to determine the namespace we're running in.
	namespace, err := os.ReadFile(winutils.GetHostPath("/var/run/secrets/kubernetes.io/serviceaccount/namespace"))
	if err != nil {
		logrus.WithError(err).Warn("Failed to read service account namespace file, defaulting to 'calico-system'")
		namespace = []byte("calico-system")
	}

	c := &policyMigrator{
		ctx:           ctx,
		cli:           cli,
		cs:            cs,
		bc:            cli.(bapi.BackendAccessor).Backend(),
		doWork:        make(chan struct{}, 1),
		pendingWork:   set.New[model.ResourceKey](),
		kvps:          make(map[model.ResourceKey]*model.KVPair),
		updates:       make(chan bapi.Update, utils.BatchUpdateSize),
		statusUpdates: make(chan bapi.SyncStatus),
		namespace:     string(namespace),
		skipRollout:   os.Getenv("FV_TEST") == "true",
	}
	c.RegisterWith(feed)

	return c
}

type policyMigrator struct {
	ctx                  context.Context
	cli                  clientv3.Interface
	cs                   kubernetes.Interface
	bc                   bapi.Client
	initialSyncCompleted bool

	// State
	kvps        map[model.ResourceKey]*model.KVPair
	pendingWork set.Set[model.ResourceKey]

	// Channels
	doWork        chan struct{}
	updates       chan bapi.Update
	statusUpdates chan bapi.SyncStatus

	// Configuration.
	namespace string

	// For FV testing - allows skipping the calico-node rollout wait.
	skipRollout bool
}

func (c *policyMigrator) RegisterWith(f *utils.DataFeed) {
	// Register for updates for policy resources.
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)

	// Register for sync status updates.
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *policyMigrator) onStatusUpdate(status bapi.SyncStatus) {
	c.statusUpdates <- status
}

func (c *policyMigrator) onUpdate(update bapi.Update) {
	switch update.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case v3.KindNetworkPolicy,
			v3.KindGlobalNetworkPolicy,
			v3.KindStagedNetworkPolicy,
			v3.KindStagedGlobalNetworkPolicy:
			// We care about these kinds.
			// Send the update to the processing channel.
			c.updates <- update
		}
	}
}

func (c *policyMigrator) kick() {
	select {
	case c.doWork <- struct{}{}:
		// Successfully sent kick.
	default:
		// Kick already pending.
	}
}

func (c *policyMigrator) Run(stop chan struct{}) {
	logrus.Info("Starting policy migration controller")

	// Start a goroutine to handle updates.
	go c.run(stop)

	<-stop
	logrus.Info("Stopping policy migration controller")
}

// run is the main loop for the controller, processing updates and status changes and triggering work.
func (c *policyMigrator) run(stop chan struct{}) {
	// Wait for calico-node rollout to complete before starting migration.
	err := c.waitForCalicoNodeRollout()
	if err != nil {
		logrus.Errorf("Error waiting for calico-node rollout: %v", err)
	}

	for {
		select {
		case <-stop:
			return
		case status := <-c.statusUpdates:
			if status == bapi.InSync && !c.initialSyncCompleted {
				c.initialSyncCompleted = true
			}
			logrus.Infof("Syncer status updated: %s", status.String())
			c.kick()
		case updates := <-c.updates:
			logEntry := logrus.WithFields(logrus.Fields{"controller": "PolicyMigrator"})
			utils.ProcessBatch(c.updates, updates, c.processUpdates, logEntry)
			c.kick()
		case <-time.After(5 * time.Minute):
			// Periodic kick to reprocess pending work. This handles any missed updates or transient errors.
			// Ideally, we'd requeue errors immediately, but this is a safety net.
			c.kick()
		case <-c.doWork:
			err := c.processPendingWork()
			if err != nil {
				logrus.Errorf("Error processing updates: %v", err)
			}
		}
	}
}

// processUpdates processes incoming updates from the syncer and updates internal state.
func (c *policyMigrator) processUpdates(update bapi.Update) {
	// Store updates.
	kvp := update.KVPair
	key, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		logrus.Errorf("Received unexpected key type: %T", kvp.Key)
		return
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"key":  key,
		"type": update.UpdateType.String(),
	})
	logCtx.Debug("Received policy update")

	if kvp.Value == nil {
		// Deletion - remove from state.
		delete(c.kvps, kvp.Key.(model.ResourceKey))
		c.pendingWork.Discard(key)
	} else {
		// Addition or update - store in state.
		c.kvps[key] = &kvp

		// If the policy needs migration, add to pending work.
		if p, ok := kvp.Value.(client.Object); ok {
			if NeedsMigration(p, key) {
				logCtx.Debug("Stored policy for potential migration check")
				c.pendingWork.Add(key)
			} else {
				logCtx.Debug("Policy does not need migration, skipping")
				c.pendingWork.Discard(key)
			}
		}
	}
}

// processPendingWork processes policies that need migration.
func (c *policyMigrator) processPendingWork() error {
	// Wait for the initial sync to complete before doing any work.
	if !c.initialSyncCompleted {
		logrus.Debug("Initial sync not yet complete, waiting...")
		return nil
	}

	for key := range c.pendingWork.All() {
		if _, err := MigratePolicyKVP(c.ctx, c.bc, c.kvps[key]); err != nil {
			logrus.WithField("key", key).WithError(err).Error("Failed to migrate policy, will retry")
			continue
		}
		c.pendingWork.Discard(key)
	}
	return nil
}

// waitForCalicoNodeRollout waits for all calico-node pods to be running the version that supports the new policy names.
func (c *policyMigrator) waitForCalicoNodeRollout() error {
	if c.skipRollout {
		// This is useful for FV tests that don't run calico-node.
		logrus.Info("Skipping calico-node rollout wait as per configuration")
		return nil
	}

	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-time.After(5 * time.Second):
			// Rate limit checks to once every 5 seconds.
			ds, err := c.cs.AppsV1().DaemonSets(c.namespace).Get(c.ctx, "calico-node", metav1.GetOptions{})
			if err != nil {
				logrus.Errorf("Error getting calico-node DaemonSet: %v", err)
				continue
			}
			if ds.Status.ObservedGeneration != ds.Generation {
				logrus.WithFields(logrus.Fields{
					"observedGeneration": ds.Status.ObservedGeneration,
					"generation":         ds.Generation,
				}).Info("Waiting for calico-node DaemonSet to be observed")
				continue
			}
			if ds.Status.CurrentNumberScheduled != ds.Status.DesiredNumberScheduled {
				logrus.WithFields(logrus.Fields{
					"currentNumberScheduled": ds.Status.CurrentNumberScheduled,
					"desiredNumberScheduled": ds.Status.DesiredNumberScheduled,
				}).Info("Waiting for all calico-node pods to be scheduled")
				continue
			}
			if ds.Status.UpdatedNumberScheduled != ds.Status.DesiredNumberScheduled {
				logCtx := logrus.WithFields(logrus.Fields{
					"updatedNumberScheduled": ds.Status.UpdatedNumberScheduled,
					"desiredNumberScheduled": ds.Status.DesiredNumberScheduled,
				})
				logCtx.Info("Waiting for all calico-node pods to be updated")
				continue
			}
			if ds.Status.NumberUnavailable > 0 {
				logCtx := logrus.WithFields(logrus.Fields{
					"numberUnavailable": ds.Status.NumberUnavailable,
				})
				logCtx.Info("Waiting for all calico-node pods to be available")
				continue
			}
			if ds.Status.NumberMisscheduled > 0 {
				logCtx := logrus.WithFields(logrus.Fields{
					"numberMisscheduled": ds.Status.NumberMisscheduled,
				})
				logCtx.Info("Waiting for all calico-node pods to be correctly scheduled")
				continue
			}
			logrus.Info("All calico-node pods are up-to-date")
			return nil
		}
	}
}
