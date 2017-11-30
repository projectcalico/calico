//+build windows

package windataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/dataplane-drivers/windataplane/policysets"
)

// policyManager simply passes through Policy and Profile updates from the datastore to the
// PolicySets dataplane layer.
type policyManager struct {
	policysetsDataplane policysets.PolicySetsDataplane
}

func newPolicyManager(policysets policysets.PolicySetsDataplane) *policyManager {
	return &policyManager{
		policysetsDataplane: policysets,
	}
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *policyManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.ActivePolicyUpdate:
		log.WithField("policyID", msg.Id).Info("Processing ActivePolicyUpdate")
		m.policysetsDataplane.AddOrReplacePolicySet(msg.Id.Name, msg.Policy)
	case *proto.ActivePolicyRemove:
		log.WithField("policyID", msg.Id).Info("Processing ActivePolicyRemove")
		m.policysetsDataplane.RemovePolicySet(msg.Id.Name)
	case *proto.ActiveProfileUpdate:
		log.WithField("profileId", msg.Id).Info("Processing ActiveProfileUpdate")
		m.policysetsDataplane.AddOrReplacePolicySet(msg.Id.Name, msg.Profile)
	case *proto.ActiveProfileRemove:
		log.WithField("profileId", msg.Id).Info("Processing ActiveProfileRemove")
		m.policysetsDataplane.RemovePolicySet(msg.Id.Name)
	}
}

func (m *policyManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
