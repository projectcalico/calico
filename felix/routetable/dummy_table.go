package routetable

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
)

type DummyTable struct {
}

func (_ *DummyTable) OnIfaceStateChanged(_ string, _ int, _ ifacemonitor.State) {
}

func (_ *DummyTable) QueueResync() {
}

func (_ *DummyTable) QueueResyncIface(string) {
}

func (_ *DummyTable) Apply() error {
	return nil
}

func (_ *DummyTable) SetRoutes(routeClass RouteClass, ifaceName string, targets []Target) {
}

func (_ *DummyTable) RouteRemove(routeClass RouteClass, ifaceName string, cidr ip.CIDR) {
}

func (_ *DummyTable) RouteUpdate(routeClass RouteClass, ifaceName string, target Target) {
}

func (_ *DummyTable) Index() int {
	return 0
}

func (_ *DummyTable) ReadRoutesFromKernel(ifaceName string) ([]Target, error) {
	return nil, nil
}

func (_ *DummyTable) SetRemoveExternalRoutes(b bool) {
}
