package routetable

import "github.com/projectcalico/felix/ifacemonitor"

type DummyTable struct {
}

func (_ *DummyTable) OnIfaceStateChanged(_ string, _ ifacemonitor.State) {
	return
}

func (_ *DummyTable) QueueResync() {

}

func (_ *DummyTable) Apply() error {
	return nil
}

func (_ *DummyTable) SetRoutes(_ string, _ []Target) {
	return
}

func (_ *DummyTable) SetL2Routes(_ string, _ []L2Target) {
	return
}
