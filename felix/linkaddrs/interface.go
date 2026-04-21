package linkaddrs

import (
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
)

// Interface is the interface provided by the standard linkaddrs module. Made to support multiple implementations (standard and no-op)
type Interface interface {
	QueueResync()
	SetLinkLocalAddress(_ string, _ ip.CIDR) error
	RemoveLinkLocalAddress(_ string)
	GetNlHandle() (netlinkshim.Interface, error)
	Apply() error
}
