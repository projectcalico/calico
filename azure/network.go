package azure

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

var networksDir string = "/var/run/calico/azure/networks/"

// AzureNetwork facilitates the manipulation of state associated with an Azure
// network. It can be stored and used across executions of the plugin.
type AzureNetwork struct {
	Name    string
	Subnets []string
}

func (an *AzureNetwork) Write() error {
	// Make sure the directory exists.
	err := an.ensureDir()
	if err != nil {
		return err
	}

	// Write the network struct to disk.
	bytes, err := json.Marshal(an)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(an.filename(), bytes, 0600); err != nil {
		return err
	}
	logrus.Infof("Stored AzureNetwork: %#v", an)
	return nil
}

func (an *AzureNetwork) Load() error {
	bytes, err := ioutil.ReadFile(an.filename())
	if err != nil {
		return nil
	}
	logrus.Infof("Loaded AzureNetwork: %s", bytes)
	return json.Unmarshal(bytes, an)
}

func (an *AzureNetwork) filename() string {
	return fmt.Sprintf(networksDir + an.Name + "/network.json")
}

func (an *AzureNetwork) ensureDir() error {
	return os.MkdirAll(networksDir+an.Name, os.ModePerm)
}
