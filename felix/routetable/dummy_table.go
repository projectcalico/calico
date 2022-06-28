package routetable

import (
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
)

type DummyTable struct {
}

func (_ *DummyTable) OnIfaceStateChanged(_ string, _ ifacemonitor.State) {
}

func (_ *DummyTable) QueueResync() {

}

func (_ *DummyTable) Apply() error {
	return nil
}

func (_ *DummyTable) SetRoutes(_ string, _ []Target) {
}

func (_ *DummyTable) SetL2Routes(_ string, _ []L2Target) {
}

func (_ *DummyTable) RouteRemove(_ string, _ ip.CIDR) {
}

func (_ *DummyTable) RouteUpdate(_ string, _ Target) {
}
