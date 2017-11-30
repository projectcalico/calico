//+build windows

package windataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/dataplane-drivers/windataplane/ipsets"
)

// ipSetsManager simply passes through IP set updates from the datastore to the ipsets.IPSets
// dataplane layer.
type ipSetsManager struct {
	ipsetsDataplane ipsets.IPSetsDataplane
}

func newIPSetsManager(ipsets ipsets.IPSetsDataplane) *ipSetsManager {
	return &ipSetsManager{
		ipsetsDataplane: ipsets,
	}
}

// OnUpdate is called by the main dataplane driver loop during the first phase. It processes
// specific types of updates from the datastore.
func (m *ipSetsManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetDeltaUpdate")
		m.ipsetsDataplane.AddMembers(msg.Id, msg.AddedMembers)
		m.ipsetsDataplane.RemoveMembers(msg.Id, msg.RemovedMembers)
	case *proto.IPSetUpdate:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetUpdate")
		metadata := ipsets.IPSetMetadata{
			Type:    ipsets.IPSetTypeHashIP,
			SetID:   msg.Id,
		}
		m.ipsetsDataplane.AddOrReplaceIPSet(metadata, msg.Members)
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Info("Processing IPSetRemove")
		m.ipsetsDataplane.RemoveIPSet(msg.Id)
	}
}

func (m *ipSetsManager) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}
