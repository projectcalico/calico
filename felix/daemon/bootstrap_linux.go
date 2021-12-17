package daemon

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/wireguard"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

func bootstrapWireguard(ifaceName string, felixHostName string, v3Client clientv3.Interface) {
	err := wireguard.BootstrapHostConnectivity(
		ifaceName, felixHostName, v3Client)

	if err != nil {
		log.WithError(err).Info("couldn't bootstrap wireguard host connectivity")
	}
}
