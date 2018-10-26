package azure

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

// AzureEndpoint represents a container networked using Calico in conjunction with
// the azure-vnet-ipam plugin. We need to store state about the containers we've networked
// so we can pass the correct information to the IPAM plugin on delete. This structure
// handles the manipulation of that state.
type AzureEndpoint struct {
	Network     string
	ContainerID string
	Interface   string
	Addresses   []string
}

func (ae *AzureEndpoint) Write() error {
	bytes, err := json.Marshal(ae)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(ae.filename(), bytes, 0600); err != nil {
		return err
	}
	logrus.Infof("Stored AzureEndpoint: %#v", ae)
	return nil
}

func (ae *AzureEndpoint) Load() error {
	bytes, err := ioutil.ReadFile(ae.filename())
	if err != nil {
		return nil
	}
	logrus.Infof("Loaded AzureEndpoint: %s", bytes)
	return json.Unmarshal(bytes, ae)
}

func (ae *AzureEndpoint) Delete() error {
	logrus.Infof("Deleting AzureEndpoint: %#v", ae)
	return os.Remove(ae.filename())
}

func (ae *AzureEndpoint) filename() string {
	return fmt.Sprintf("%s/%s/%s-%s",
		networksDir,
		ae.Network,
		ae.ContainerID,
		ae.Interface,
	)
}
