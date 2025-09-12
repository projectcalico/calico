package routetable

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
)

type DummyTable struct {
}

func (*DummyTable) OnIfaceStateChanged(_ string, _ int, _ ifacemonitor.State) {
}

func (*DummyTable) QueueResync() {
}

func (*DummyTable) QueueResyncIface(string) {
}

func (*DummyTable) Apply() error {
	return nil
}

func (*DummyTable) SetRoutes(routeClass RouteClass, ifaceName string, targets []Target) {
}

func (*DummyTable) RouteRemove(routeClass RouteClass, ifaceName string, cidr ip.CIDR) {
}

func (*DummyTable) RouteUpdate(routeClass RouteClass, ifaceName string, target Target) {
}

func (*DummyTable) Index() int {
	return 0
}

func (*DummyTable) ReadRoutesFromKernel(ifaceName string) ([]Target, error) {
	return nil, nil
}

func (*DummyTable) SetRemoveExternalRoutes(b bool) {
}
