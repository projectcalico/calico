package backends

import (
	"github.com/kelseyhightower/confd/pkg/backends/calico"
)

// The StoreClient interface is implemented by objects that can retrieve
// key/value pairs from a backend store.
type StoreClient interface {
	SetPrefixes(keys []string) error
	GetValues(keys []string) (map[string]string, error)
	WatchPrefix(prefix string, keys []string, waitIndex uint64, stopChan chan bool) error
	GetCurrentRevision() uint64
}

// New is used to create a storage client based on our configuration.
func New(config Config) (StoreClient, error) {
	return calico.NewCalicoClient(config.Calicoconfig, config.RouteReflector)
}
