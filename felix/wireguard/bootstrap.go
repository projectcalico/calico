package wireguard

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// BootstrapHostConnectivity forces WireGuard peers with hostencryption enabled to communicate with this node unencrypted.
// This ensures connectivity in scenarios where we have lost our WireGuard config, but will be sent WireGuard traffic
// e.g. after a node restart, during felix startup, when we need to fetch config from Typha (calico/issues/5125)
func BootstrapHostConnectivity(wgDeviceName string, nodeName string, calicoClient clientv3.Interface) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	thisNode, err := calicoClient.Nodes().Get(ctx, nodeName, options.GetOptions{})
	cancel()
	if err != nil {
		log.WithError(err).Warn("could not fetch node config from datastore")
		return err
	}

	storedPublicKey := thisNode.Status.WireguardPublicKey
	kernelPublicKey := getPublicKey(wgDeviceName, netlinkshim.NewRealWireguard)

	// if there is any config mismatch, wipe the datastore's publickey (forces peers to send unencrypted traffic)
	if storedPublicKey != kernelPublicKey.String() {
		thisNode.Status.WireguardPublicKey = ""

		maxRetries := 3
		for r := 0; r < maxRetries; r++ {
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			_, err := calicoClient.Nodes().Update(ctx, thisNode, options.SetOptions{})
			cancel()
			if err != nil {
				switch err.(type) {
				case cerrors.ErrorResourceUpdateConflict:
					log.Debug("conflict while clearing wireguard config, retrying update")
					continue
				}
				log.WithError(err).Warn("failed to clear wireguard config")
				return err
			}
		}
	}
	return nil
}

// getPublicKey attempts to fetch a wireguard key from the kernel statelessly
func getPublicKey(wgIfaceName string, getWireguardHandle func() (netlinkshim.Wireguard, error)) wgtypes.Key {
	wg, err := getWireguardHandle()
	if err != nil {
		log.WithError(err).Info("couldn't acquire WireGuard handle")
		return zeroKey
	}
	defer wg.Close()

	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		log.WithError(err).Infof("couldn't find wireguard device '%s'", wgIfaceName)
		return zeroKey
	}

	return dev.PublicKey
}
