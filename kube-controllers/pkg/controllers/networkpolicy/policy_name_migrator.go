package networkpolicy

import (
	"context"
	"os"
	"reflect"
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
	liberr "github.com/projectcalico/calico/libcalico-go/lib/errors"
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
	type accessor interface {
		Backend() bapi.Client
	}

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
		bc:            cli.(accessor).Backend(),
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
	ctx    context.Context
	cli    clientv3.Interface
	cs     kubernetes.Interface
	bc     bapi.Client
	status bapi.SyncStatus

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
	// Register for updates for NetworkPolicy and GlobalNetworkPolicy.
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
			c.status = status
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
			if needsMigration(p, key) {
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
	// Wait for the syncer to be in sync.
	if c.status != bapi.InSync {
		logrus.Debug("Syncer not in sync yet, waiting...")
		return nil
	}

	// No-op for now.
	for key := range c.pendingWork.All() {
		kvp := c.kvps[key]
		p := kvp.Value.(client.Object)
		k := kvp.Key.(model.ResourceKey)

		logCtx := logrus.WithFields(logrus.Fields{
			"namespace": p.GetNamespace(),
			"v3name":    p.GetName(),
			"kind":      p.GetObjectKind().GroupVersionKind().Kind,
		})
		logCtx.Debug("Processing policy for potential migration")

		// The name in the Key is the actual v1 ID used in the datastore, whereas the ObjectMeta.Name is the v3
		// object name. If they differ, we need to correct the underlying datastore entry to align with the v3 naming.
		if !needsMigration(p, k) {
			logCtx.Debug("No migration needed")
			c.pendingWork.Discard(key)
			continue
		}

		logCtx.WithFields(logrus.Fields{
			"v1Name": k.Name,
		}).Debug("Migrating policy to new name")

		// Create a new Policy object with the correct v3 name.
		newPolicy := p.DeepCopyObject()
		newKey := k
		newKey.Name = p.GetName()

		// Create the new policy in the datastore.
		_, err := c.bc.Create(c.ctx, &model.KVPair{Key: newKey, Value: newPolicy})
		if err != nil {
			if _, ok := err.(liberr.ErrorResourceAlreadyExists); !ok {
				// If the error is AlreadyExists, it means we already fixed this policy in a previous run, so we can safely ignore it.
				// For other errors, log them and continue on to the next piece of work.
				logCtx.Errorf("Error creating new policy %s: %v", newKey, err)
				continue
			}
			logCtx.Infof("New policy %s already exists, carry on", newKey)
		}

		// Delete the old policy from the datastore.
		_, err = c.bc.DeleteKVP(c.ctx, kvp)
		if err != nil {
			if _, ok := err.(liberr.ErrorResourceDoesNotExist); !ok {
				// If the error is NotFound, it means the old policy was already deleted, so we can safely ignore it.
				// For other errors, log them and continue on to the next piece of work.
				logCtx.Errorf("Error deleting old policy %s: %v", k, err)
				continue
			}
			logCtx.Infof("Old policy %s already deleted, carry on", k)
		}

		// Successfully migrated this policy, remove from pending work.
		logrus.WithFields(logrus.Fields{
			"namespace": p.GetNamespace(),
			"newName":   p.GetName(),
			"oldName":   k.Name,
			"kind":      p.GetObjectKind().GroupVersionKind().Kind,
		}).Info("Successfully migrated storage name for policy")
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

func needsMigration(p client.Object, k model.ResourceKey) bool {
	// The name in the Key is the actual v1 ID used in the datastore, whereas the ObjectMeta.Name is the v3
	// object name. If they differ, we need to correct the underlying datastore entry to align with the v3 naming.
	//
	// Policies in non-default tiers have traditionally had restrictive validation that prevented the mismatch
	// this controller is designed to fix. Therefore, we only need to fix policies in the default tier.
	return isDefaultTier(p) && k.Name != p.GetName()
}

func isDefaultTier(p client.Object) bool {
	logCtx := logrus.WithFields(logrus.Fields{
		"namespace": p.GetNamespace(),
		"name":      p.GetName(),
	})

	// Use reflection to get the Tier field from the policy spec.
	spec := reflect.ValueOf(p).Elem().FieldByName("Spec")
	if !spec.IsValid() {
		logCtx.Warn("Spec field not found in object")
		return true // Default to true if Spec field is not found.
	}

	tierField := spec.FieldByName("Tier")
	if !tierField.IsValid() {
		logCtx.Warn("Tier field not found in Spec")
		return true // Default to true if Tier field is not found.
	}

	tier, ok := tierField.Interface().(string)
	if !ok {
		logCtx.Warn("Tier field is not a string")
		return true // Default to true if Tier field is not a string.
	}
	return tier == "" || tier == "default"
}
