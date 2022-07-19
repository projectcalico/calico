// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	yaml "github.com/projectcalico/go-yaml-wrapper"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/crds"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	calicoErrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func Import(args []string) error {
	doc := `Usage:
  <BINARY_NAME> datastore migrate import --filename=<FILENAME> [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to import resources.  If set to
                               "-" loads from stdin.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  Import the contents of the etcdv3 datastore from the file created by the
  export command.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	// Note: Intentionally not check version mismatch for this command

	cf := parsedArgs["--config"].(string)
	cfg, err := clientmgr.LoadClientConfig(cf)
	if err != nil {
		log.Info("Error loading config")
		return err
	}

	// Set the Kubernetes client QPS to 50 if not explicitly set.
	if cfg.Spec.K8sClientQPS == float32(0) {
		cfg.Spec.K8sClientQPS = float32(50)
	}

	// Get the backend client for updating cluster info and migrating IPAM.
	client, err := client.New(*cfg)
	if err != nil {
		return err
	}

	// Check that the datastore configured datastore is kubernetes
	if cfg.Spec.DatastoreType != apiconfig.Kubernetes {
		return fmt.Errorf("Invalid datastore type: %s to import to for datastore migration. Datastore type must be kubernetes", cfg.Spec.DatastoreType)
	}

	err = importCRDs(cfg)
	if err != nil {
		return fmt.Errorf("Error applying the CRDs necessary to begin datastore import: %s", err)
	}

	err = checkCalicoResourcesNotExist(parsedArgs, client)
	if err != nil {
		// TODO: Add something like 'calicoctl datastore migrate clean' to delete all the CRDs to wipe out the Calico resources.
		return fmt.Errorf("Datastore already has Calico resources: %s. Clear out all Calico resources by deleting all Calico CRDs.", err)
	}

	// Ensure that the cluster info resource is initialized.
	ctx := context.Background()
	if err := client.EnsureInitialized(ctx, "", ""); err != nil {
		return fmt.Errorf("Unable to initialize cluster information for the datastore migration: %s", err)
	}

	// Make sure that the datastore is locked. Since the call to EnsureInitialized
	// should initialize it to unlocked, lock it before we continue.
	locked, err := common.CheckLocked(ctx, client)
	if err != nil {
		return fmt.Errorf("Error while checking if datastore was locked: %s", err)
	} else if !locked {
		err := Lock([]string{"datastore", "migrate", "lock", "-c", cf})
		if err != nil {
			return fmt.Errorf("Error while attempting to lock the datastore for import: %s", err)
		}
	}

	// Split file into v3 API, ClusterGUID, and IPAM components
	filename := parsedArgs["--filename"].(string)
	v3Yaml, clusterInfoJson, ipamJson, err := splitImportFile(filename)
	if err != nil {
		return fmt.Errorf("Error while reading migration file: %s\n", err)
	}

	// Apply v3 API resources
	err = updateV3Resources(cfg, v3Yaml)
	if err != nil {
		return fmt.Errorf("Failed to import v3 resources: %s\n", err)
	}

	// Update the clusterinfo resource with the data from the old datastore.
	err = updateClusterInfo(ctx, client, clusterInfoJson)
	if err != nil {
		return fmt.Errorf("Failed to update cluster information: %s", err)
	}

	// Import IPAM components
	fmt.Print("Importing IPAM resources\n")
	ipam := NewMigrateIPAM(client)
	err = json.Unmarshal(ipamJson, ipam)
	if err != nil {
		return fmt.Errorf("Failed to read IPAM resources: %s\n", err)
	}
	results := ipam.PushToDatastore()

	// Handle the IPAM results
	if results.numHandled == 0 {
		if results.numResources == 0 {
			return fmt.Errorf("No IPAM resources specified in file")
		} else {
			return fmt.Errorf("Failed to import any IPAM resources: %v", results.resErrs)
		}
	} else if len(results.resErrs) == 0 {
		fmt.Printf("Successfully applied %d IPAM resource(s)\n", results.numHandled)
	} else {
		if results.numHandled != 0 && len(results.resErrs) > 0 {
			fmt.Printf("Partial success: ")
			fmt.Printf("applied the first %d out of %d resources:\n", results.numHandled, results.numResources)
		}
		return fmt.Errorf("Hit error(s): %v", results.resErrs)
	}

	fmt.Print("Datastore information successfully imported. Please refer to the datastore migration documentation for next steps.\n")

	return nil
}

func splitImportFile(filename string) ([]byte, []byte, []byte, error) {
	// Get the appropriate file to read from
	fname := filename
	if filename == "-" {
		fname = os.Stdin.Name()
	}

	b, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, nil, nil, err
	}

	split := bytes.Split(b, []byte("===\n"))
	if len(split) != 3 {
		return nil, nil, nil, fmt.Errorf("Imported file: %s is improperly formatted. Try recreating with 'calicoctl export'", fname)
	}

	// First chunk should be the v3 resource YAML.
	// Second chunk should give the cluster info resource.
	// Last chunk should be the IPAM JSON.
	return split[0], split[1], split[2], nil
}

func checkCalicoResourcesNotExist(args map[string]interface{}, c client.Interface) error {
	// Loop through all the v3 resources to see if anything is returned
	extendedV3Resources := append(allV3Resources, "clusterinfo")
	for _, r := range extendedV3Resources {
		// Skip nodes since they are backed by the Kubernetes node resource
		if r == "nodes" {
			continue
		}

		// Create mocked args in order to retrieve Get resources.
		mockArgs := map[string]interface{}{
			"<KIND>":   r,
			"<NAME>":   []string{},
			"--config": args["--config"].(string),
			"--export": false,
			"--output": "ps",
			"get":      true,
		}

		if _, ok := namespacedResources[r]; ok {
			mockArgs["--all-namespaces"] = true
		}

		// Get resources
		results := common.ExecuteConfigCommand(mockArgs, common.ActionGetOrList)

		// Loop through the result lists and see if anything exists
		for _, resource := range results.Resources {
			if meta.LenList(resource) > 0 {
				if r == "networkpolicies" {
					// For networkpolicies, having K8s network policies should not throw an error
					objs, err := meta.ExtractList(resource)
					if err != nil {
						return fmt.Errorf("Error extracting network policies for inspection: %s", err)
					}

					for _, obj := range objs {
						metaObj, ok := obj.(v1.ObjectMetaAccessor)
						if !ok {
							return fmt.Errorf("Unable to convert Calico network policy for inspection")
						}

						// Make sure that the network policy is a K8s network policy
						if !strings.HasPrefix(metaObj.GetObjectMeta().GetName(), conversion.K8sNetworkPolicyNamePrefix) {
							return fmt.Errorf("Found existing Calico %s resource", results.SingleKind)
						}
					}
				} else {
					return fmt.Errorf("Found existing Calico %s resource", results.SingleKind)
				}
			}

			if results.FileInvalid {
				return fmt.Errorf("Failed to execute command: %v", results.Err)
			} else if results.Err != nil {
				return fmt.Errorf("Failed to retrieve %s resources during datastore check: %v", resourceDisplayMap[r], results.Err)
			}
		}
	}

	// Check if any IPAM resources exist
	ipam := NewMigrateIPAM(c)
	err := ipam.PullFromDatastore()
	if err != nil {
		return fmt.Errorf("Failed to retrieve IPAM resources during datastore check: %s", err)
	}

	if !ipam.IsEmpty() {
		return fmt.Errorf("Found existing IPAM resources")
	}

	return nil
}

func updateClusterInfo(ctx context.Context, c client.Interface, clusterInfoJson []byte) error {
	// Unmarshal the etcd cluster info resource.
	migrated := apiv3.ClusterInformation{}
	err := json.Unmarshal(clusterInfoJson, &migrated)
	if err != nil {
		return fmt.Errorf("Error reading exported cluster info for migration: %s", err)
	}

	// Get the "default" cluster info resource.
	clusterinfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("Error retrieving current cluster info for migration: %s", err)
	}

	// Update the calico version and cluster GUID.
	clusterinfo.Spec.ClusterGUID = migrated.Spec.ClusterGUID
	clusterinfo.Spec.CalicoVersion = migrated.Spec.CalicoVersion
	_, err = c.ClusterInformation().Update(ctx, clusterinfo, options.SetOptions{})
	if err != nil {
		return fmt.Errorf("Error updating current cluster info for migration: %s", err)
	}

	return nil
}

func updateV3Resources(cfg *apiconfig.CalicoAPIConfig, data []byte) error {
	// Create tempfile so the v3 resources can be created using Apply
	tempfile, err := ioutil.TempFile("", "v3migration")
	if err != nil {
		return fmt.Errorf("Error while creating temporary v3 migration file: %s\n", err)
	}
	defer os.Remove(tempfile.Name())

	if _, err := tempfile.Write(data); err != nil {
		return fmt.Errorf("Error while writing to temporary v3 migration file: %s\n", err)
	}

	// Create a tempfile for the config so QPS will be overwritten
	tempConfigFile, err := ioutil.TempFile("", "qpsconfig")
	if err != nil {
		return fmt.Errorf("Error while creating temporary v3 migration config file: %s\n", err)
	}
	defer os.Remove(tempConfigFile.Name())

	cfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("Error while serializing temporary v3 migration config file: %s\n", err)
	}

	if _, err := tempConfigFile.Write(cfgData); err != nil {
		return fmt.Errorf("Error while writing to temporary v3 migration config file: %s\n", err)
	}

	mockArgs := map[string]interface{}{
		"--config":   tempConfigFile.Name(),
		"--filename": tempfile.Name(),
		"apply":      true,
	}
	err = applyV3(mockArgs)
	if err != nil {
		return fmt.Errorf("Failed to import v3 resources: %s\n", err)
	}

	return nil
}

func importCRDs(cfg *apiconfig.CalicoAPIConfig) error {
	// Start a kube client
	// Create the correct config for the clientset
	config, _, err := k8s.CreateKubernetesClientset(&cfg.Spec)
	if err != nil {
		return err
	}

	// Create the apiextensions clientset
	cs, err := clientset.NewForConfig(config)
	if err != nil {
		return err
	}
	log.Debugf("Created k8s CRD ClientSet: %+v", cs)

	// Apply the CRDs
	calicoCRDs, err := crds.CalicoCRDs()
	if err != nil {
		return err
	}

	for _, crd := range calicoCRDs {
		_, err := cs.ApiextensionsV1().CustomResourceDefinitions().Create(context.Background(), crd, v1.CreateOptions{})
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				// If the CRD already exists attempt to update it.
				// Need to retrieve the current CRD first.
				currentCRD, err := cs.ApiextensionsV1().CustomResourceDefinitions().Get(context.Background(), crd.GetObjectMeta().GetName(), v1.GetOptions{})
				if err != nil {
					return fmt.Errorf("Error retrieving existing CRD to update: %s: %s", crd.GetObjectMeta().GetName(), err)
				}

				// Use the resource version so that the current CRD can be overwritten.
				crd.GetObjectMeta().SetResourceVersion(currentCRD.GetObjectMeta().GetResourceVersion())

				// Update the CRD.
				_, err = cs.ApiextensionsV1().CustomResourceDefinitions().Update(context.Background(), crd, v1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("Error updating CRD %s: %s", crd.GetObjectMeta().GetName(), err)
				}
			} else {
				return fmt.Errorf("Error creating CRD %s: %s", crd.GetObjectMeta().GetName(), err)
			}
		}
		log.Debugf("Applied %s CRD", crd.GetObjectMeta().GetName())
	}

	return nil
}

func applyV3(args map[string]interface{}) error {
	results := common.ExecuteConfigCommand(args, common.ActionApply)
	log.Infof("results: %+v", results)

	if results.FileInvalid {
		return fmt.Errorf("Failed to execute command: %v", results.Err)
	} else if results.NumHandled == 0 {
		return fmt.Errorf("Failed to apply any resources: %v", results.ResErrs)
	} else if len(results.ResErrs) == 0 {
		if results.SingleKind != "" {
			fmt.Printf("Successfully applied %d '%s' resource(s)\n", results.NumHandled, results.SingleKind)
		} else {
			fmt.Printf("Successfully applied %d resource(s)\n", results.NumHandled)
		}
	} else {
		// Inspect the errors. If a node does not match an existing k8s node, trigger a warning instead.
		errors := []error{}
		for _, err := range results.ResErrs {
			switch e := err.(type) {
			case calicoErrors.ErrorResourceDoesNotExist:
				// Check that the error is for a Node
				if key, ok := e.Identifier.(model.ResourceKey); ok {
					if key.Kind == libapiv3.KindNode {
						fmt.Printf("[WARNING] Attempted to import node %v from etcd that references a non-existent Kubernetes node. Skipping that node. Non-Kubernetes nodes are not supported in the Kubernetes datastore and will be skipped.", e.Identifier)
						continue
					}
				}
				errors = append(errors, err)
			default:
				errors = append(errors, err)
			}
		}

		if len(errors) > 0 {
			return fmt.Errorf("Hit error(s): %v", errors)
		}
	}

	return nil
}
