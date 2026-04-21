package linkaddrs

import (
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
)

type DummyLinkAddrsManager struct {
}

func (*DummyLinkAddrsManager) QueueResync() {
}

func (*DummyLinkAddrsManager) SetLinkLocalAddress(_ string, _ ip.CIDR) error {
	return nil
}

func (*DummyLinkAddrsManager) RemoveLinkLocalAddress(_ string) {
}

func (*DummyLinkAddrsManager) GetNlHandle() (netlinkshim.Interface, error) {
	return nil, nil
}

func (*DummyLinkAddrsManager) Apply() error {
	return nil
}
