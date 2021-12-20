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
		log.WithError(err).Info("could not fetch node config from datastore")
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
					log.Debug("conflict while clearing WireGuard config, retrying update")
					continue
				}
				log.WithError(err).Info("failed to clear WireGuard config")
				return err
			}
			log.Debugf("cleared WireGuard public key from datastore")
		}
	}
	return nil
}

// getPublicKey attempts to fetch a wireguard key from the kernel statelessly
// this is intended for use during startup; an error may simply mean wireguard is not configured
func getPublicKey(wgIfaceName string, getWireguardHandle func() (netlinkshim.Wireguard, error)) wgtypes.Key {
	wg, err := getWireguardHandle()
	if err != nil {
		log.WithError(err).Debug("couldn't acquire WireGuard handle, reporting 'zerokey' public key")
		return zeroKey
	}
	defer wg.Close()

	dev, err := wg.DeviceByName(wgIfaceName)
	if err != nil {
		log.WithError(err).Debugf("couldn't find WireGuard device '%s', reporting 'zerokey' public key", wgIfaceName)
		return zeroKey
	}

	return dev.PublicKey
}
