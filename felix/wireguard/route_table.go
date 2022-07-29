package wireguard

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/routetable"
)

// routeTableSyncer is the interface used to manage data-sync of route table managers. This includes notification of
// interface state changes, hooks to queue a full resync and apply routing updates.
type routeTableSyncer interface {
	OnIfaceStateChanged(string, ifacemonitor.State)
	QueueResync()
	Apply() error
}

// routeTable is the interface provided by the standard routetable module used to progam the RIB.
type routeTable interface {
	routeTableSyncer
	SetRoutes(ifaceName string, targets []routetable.Target)
	SetL2Routes(ifaceName string, targets []routetable.L2Target)
	RouteRemove(ifaceName string, cidr ip.CIDR)
	RouteUpdate(ifaceName string, target routetable.Target)
}
