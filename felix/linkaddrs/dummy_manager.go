package linkaddrs

import (
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
)

type DummyLinkAddrsManager struct {
}

func (_ *DummyLinkAddrsManager) QueueResync() {
}

func (_ *DummyLinkAddrsManager) SetLinkLocalAddress(_ string, _ ip.CIDR) error {
	return nil
}

func (_ *DummyLinkAddrsManager) RemoveLinkLocalAddress(_ string) {
}

func (_ *DummyLinkAddrsManager) GetNlHandle() (netlinkshim.Interface, error) {
	return nil, nil
}

func (_ *DummyLinkAddrsManager) Apply() error {
	return nil
}
