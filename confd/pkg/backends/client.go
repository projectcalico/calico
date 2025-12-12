package backends

import (
	"github.com/projectcalico/calico/confd/pkg/backends/types"
)

// The StoreClient interface is implemented by objects that can retrieve
// key/value pairs from a backend store.
type StoreClient interface {
	SetPrefixes(keys []string) error
	GetValues(keys []string) (map[string]string, error)
	WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) (string, error)
	GetCurrentRevision() uint64
	GetBirdBGPConfig(ipVersion int) (*types.BirdBGPConfig, error)
}
