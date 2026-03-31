package routetable

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
)

type DummyTable struct {
}

func (d *DummyTable) OnIfaceStateChanged(_ string, _ int, _ ifacemonitor.State) {
}

func (d *DummyTable) QueueResync() {
}

func (d *DummyTable) QueueResyncIface(string) {
}

func (d *DummyTable) Apply() error {
	return nil
}

func (d *DummyTable) SetRoutes(routeClass RouteClass, ifaceName string, targets []Target) {
}

func (d *DummyTable) RouteRemove(routeClass RouteClass, ifaceName string, cidr ip.CIDR) {
}

func (d *DummyTable) RouteUpdate(routeClass RouteClass, ifaceName string, target Target) {
}

func (d *DummyTable) Index() int {
	return 0
}

func (d *DummyTable) ReadRoutesFromKernel(ifaceName string) ([]Target, error) {
	return nil, nil
}

func (d *DummyTable) SetRemoveExternalRoutes(b bool) {
}
