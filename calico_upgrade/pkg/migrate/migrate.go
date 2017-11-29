// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_upgrade/pkg/upgradeclients"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/upgrade/etcd/conversionv1v3"
	validatorv3 "github.com/projectcalico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/yaml"
)

const (
	forceEnableReadyRetries = 10
)

var verbose = false

func SetVerboseMessages(v bool) {
	verbose = v
}

var displayStatus = false

func DisplayStatusMessages(d bool) {
	displayStatus = d
}

type ConvertedData struct {
	// The converted resources
	Resources []conversionv1v3.Resource

	// The converted resource names
	NameConversions []NameConversion

	// Errors hit attempting to convert the v1 data to v3 format
	ConversionErrors []ConversionError

	// Errors hit validating the converted v3 data.  This suggests an error in the
	// conversion script which should be fixed before reattempting the conversion.
	ConversedValidationErrors []ConversionError

	// Name clashes in the converted resources.  These need to be resolved through
	// reconfiguration before attempting the upgrade.
	NameClashes []ConversionError

	// Entries that were skipped because they will be handled by the Kubernetes
	// Policy controller.
	HandledByPolicyCtrl []model.Key
}

func (c *ConvertedData) HasErrors() bool {
	return len(c.ConversedValidationErrors) != 0 ||
		len(c.NameClashes) != 0 ||
		len(c.ConversedValidationErrors) != 0
}

type ConversionError struct {
	Msg         string
	Cause       error
	V1Key       model.Key
	V1Value     interface{}
	V3Converted conversionv1v3.Resource
}

// Details about name/id conversions.
type NameConversion struct {
	Kind     string
	Original string
	New      string
}

func (c ConversionError) String() string {
	if c.Cause == nil && c.V1Key == nil && c.V1Value == nil && c.V3Converted == nil {
		return c.Msg
	}
	msg := c.Msg + ":"
	if c.Cause != nil {
		msg += fmt.Sprintf("\n -  Cause: %v", c.Cause)
	}
	if c.V1Key != nil {
		msg += fmt.Sprintf("\n -  Original resource name: %s", c.V1Key)
	}
	if c.V3Converted != nil {
		if data, err := yaml.Marshal(c.V3Converted); err != nil {
			msg += fmt.Sprintf("\n -  Converted resource (raw): %v", c.V3Converted)
		} else {
			msg += fmt.Sprintf("\n -  Converted resource: \n%s\n", data)
		}
	}
	if c.V1Value != nil && verbose {
		if data, err := yaml.Marshal(c.V1Value); err != nil {
			msg += fmt.Sprintf("\n -  Original v1 data (raw): %v", c.V1Value)
		} else {
			msg += fmt.Sprintf("\n -  Original v1 data: \n%s\n", data)
		}
	}

	return msg
}

type policyCtrlFilterOut func(model.Key) bool

var noFilter = func(_ model.Key) bool { return false }

// QueryAndConvertResources queries the v1 resources and converts them to the equivalent
// v3 resources.
// This method returns an error if it is unable to query the current v1 settings.
// Errors from the conversion are returned within the ConvertedData - this function will
// attempt to convert everything before returning with the set of converted data and
// conversion errors - this allows a full pre-migration report to be generated in a single
// shot.
func QueryAndConvertResources(clientv1 upgradeclients.V1ClientInterface) (*ConvertedData, error) {
	res := &ConvertedData{}

	// Query the global BGP configuration:  default AS number; node-to-node mesh.
	if err := queryAndConvertGlobalBGPConfig(clientv1, res); err != nil {
		return nil, err
	}

	// Query and convert global felix configuration and cluster info.
	fc := &felixConfig{}
	if err := fc.queryAndConvertFelixConfigV1ToV3(clientv1, res); err != nil {
		return nil, err
	}

	// Query and convert the BGPPeers
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.GlobalBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.NodeBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}

	// Query and convert the HostEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.HostEndpointListOptions{}, conversionv1v3.HostEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	// Query and convert the IPPools
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.IPPoolListOptions{}, conversionv1v3.IPPool{}, noFilter,
	); err != nil {
		return nil, err
	}

	// Query and convert the Nodes
	if err := queryAndConvertV1ToV3Nodes(clientv1, res); err != nil {
		return nil, err
	}

	// Query and convert the Policies
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.PolicyListOptions{}, conversionv1v3.Policy{}, noFilter,
	); err != nil {
		return nil, err
	}

	// Query and convert the Profiles
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.ProfileListOptions{}, conversionv1v3.Profile{}, noFilter,
	); err != nil {
		return nil, err
	}

	// Query and convert the WorkloadEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.WorkloadEndpointListOptions{}, conversionv1v3.WorkloadEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	return res, nil
}

func queryAndConvertGlobalBGPConfig(clientv1 upgradeclients.V1ClientInterface, res *ConvertedData) error {
	globalBGPConfig := apiv3.NewBGPConfiguration()
	globalBGPConfig.Name = "default"

	log.Info("Converting BGP config -> BGPConfiguration(default)")
	if kvp, err := clientv1.Get(model.GlobalBGPConfigKey{Name: "AsNumber"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global default ASNumber configured")
	} else if kvp.Value.(string) != "" {
		asNum, err := numorstring.ASNumberFromString(kvp.Value.(string))
		if err != nil {
			log.WithError(err).WithField("ASNumber", kvp.Value).Info("Invalid global default ASNumber")
			res.ConversionErrors = append(res.ConversionErrors, ConversionError{
				V1Value: kvp.Value,
				Msg:     "default ASNumber is not valid",
				Cause:   err,
			})
			return err
		}
		globalBGPConfig.Spec.ASNumber = &asNum
	}

	if kvp, err := clientv1.Get(model.GlobalBGPConfigKey{Name: "LogLevel"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global BGP log level configured")
	} else if kvp.Value.(string) != "" {
		globalBGPConfig.Spec.LogSeverityScreen = convertLogLevel(kvp.Value.(string))
	}

	if kvp, err := clientv1.Get(model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global node to node mesh enabled setting configured")
	} else if kvp.Value.(string) != "" {
		nodeMeshEnabled := strings.ToLower(kvp.Value.(string)) == "true"
		globalBGPConfig.Spec.NodeToNodeMeshEnabled = &nodeMeshEnabled
	}
	res.Resources = append(res.Resources, globalBGPConfig)
	return nil
}

// Query the v1 format resources and convert to the v3 format.  Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func queryAndConvertV1ToV3Resources(
	clientv1 upgradeclients.V1ClientInterface,
	res *ConvertedData,
	listInterface model.ListInterface,
	converter conversionv1v3.Converter,
	filterOut policyCtrlFilterOut,
) error {
	// Start by listing the results from the v1 client.
	kvps, err := clientv1.List(listInterface)
	if err != nil {
		switch err.(type) {
		case cerrors.ErrorResourceDoesNotExist, cerrors.ErrorOperationNotSupported:
			return nil
		default:
			return err
		}
	}

	// Keep track of the converted names so that we can determine if we have any
	// name clashes.  We don't generally expect this, but we do need to police against
	// it just in case.
	convertedNames := make(map[string]model.Key, len(kvps))

	// Pass the results through the supplied converter and check that each result
	// validates.
	for _, kvp := range kvps {
		if filterOut(kvp.Key) {
			log.Infof("Filter out Policy Controller created resource: %s", kvp.Key)
			res.HandledByPolicyCtrl = append(res.HandledByPolicyCtrl, kvp.Key)
		}

		r, err := converter.BackendV1ToAPIV3(kvp)
		if err != nil {
			res.ConversionErrors = append(res.ConversionErrors, ConversionError{
				V1Key:   kvp.Key,
				V1Value: kvp.Value,
				Msg:     "error occurred converting the resource",
				Cause:   err,
			})
			continue
		}

		// Check the converted name for clashes.  Store an error if there is a clash and
		// continue with additional checks so that we output as much information as possible.
		valid := true
		convertedName := r.GetObjectMeta().GetNamespace() + "/" + r.GetObjectMeta().GetName()
		if k, ok := convertedNames[convertedName]; ok {
			res.NameClashes = append(res.NameClashes, ConversionError{
				V1Key:       kvp.Key,
				V3Converted: r,
				Msg:         fmt.Sprintf("converted resource name clashes with the name of the following v1 resource: %s", k),
			})
			valid = false
		}
		convertedNames[convertedName] = kvp.Key

		// Check the converted resource validates correctly.
		if err := validatorv3.Validate(r); err != nil {
			res.ConversedValidationErrors = append(res.ConversedValidationErrors, ConversionError{
				V1Key:       kvp.Key,
				V1Value:     kvp.Value,
				V3Converted: r,
				Msg:         "converted resource does not validate correctly",
				Cause:       err,
			})
			valid = false
		}

		// Only store the resource if it's valid.
		if valid {
			res.Resources = append(res.Resources, r)
		}
	}

	return nil
}

// Query the v1 format resources and convert to the v3 format.  Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func queryAndConvertV1ToV3Nodes(
	v1Client upgradeclients.V1ClientInterface,
	res *ConvertedData,
) error {
	// Start by querying the nodes and converting them, we don't add the nodes to the list
	// of results just yet.
	var nodes []conversionv1v3.Resource
	err := queryAndConvertV1ToV3Resources(
		v1Client, res,
		model.NodeListOptions{}, conversionv1v3.Node{}, noFilter,
	)
	if err != nil {
		return err
	}

	// Query all of the per-node config and extract all of the IPIP tunnel addresses that are
	// configured.
	kvps, err := v1Client.List(model.HostConfigListOptions{Name: "IpInIpTunnelAddr"})
	if err != nil {
		switch err.(type) {
		case cerrors.ErrorResourceDoesNotExist, cerrors.ErrorOperationNotSupported:
			return nil
		default:
			return err
		}
	}
	addrs := map[string]string{}
	for _, kvp := range kvps {
		k := kvp.Key.(model.HostConfigKey)
		addrs[conversionv1v3.ConvertNodeName(k.Hostname)] = kvp.Value.(string)
	}

	// Update the node resources to include the tunnel addresses.
	for _, node := range nodes {
		nr := node.(*apiv3.Node)
		addr := addrs[nr.Name]
		if addr == "" || nr.Spec.BGP == nil {
			continue
		}
		nr.Spec.BGP.IPv4IPIPTunnelAddr = addr
	}

	// Now the nodes are updated, append them to the full list of results.
	res.Resources = append(res.Resources, nodes...)

	return nil
}

// convertLogLevel converts the v1 log level to the equivalent v3 log level.  We
// ignore errors, defaulting to info in the event of a conversion error.
func convertLogLevel(logLevel string) string {
	switch strings.ToLower(logLevel) {
	case "debug":
		return "Debug"
	case "info":
		return "Info"
	case "warning":
		return "Warning"
	case "error":
		return "Error"
	case "fatal":
		return "Fatal"
	case "panic":
		return "Fatal"
	case "":
		return ""
	default:
		return "Info"
	}
}

func status(msg string) {
	log.Info(msg)
	if displayStatus {
		fmt.Println(msg)
	}
}

func SetReadyV1(clientv1 upgradeclients.V1ClientInterface, ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v1")
	_, err := clientv1.Apply(&model.KVPair{
		Key:   model.ReadyFlagKey{},
		Value: ready,
	})
	if err != nil {
		if ready {
			status("- Failed to enable Calico networking in the v1 configuration")
		} else {
			status("- Failed to disable Calico networking in the v1 configuration")
		}
	}
	if ready {
		status("- Successfully enabled Calico networking in the v1 configuration")
	} else {
		status("- Successfully disabled Calico networking in the v1 configuration")
	}
	return nil
}

func SetReadyV3(clientv3 clientv3.Interface, ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v3")
	c, err := clientv3.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// ClusterInformation already exists - update the settings.
		log.WithField("Ready", ready).Info("Updating Ready flag in v3 ClusterInformation")
		c.Spec.DatastoreReady = &ready
		_, err = clientv3.ClusterInformation().Update(context.Background(), c, options.SetOptions{})
		if err != nil {
			if ready {
				status("- Failed to enable Calico networking in the v3 configuration (unable to update ClusterInformation)")
			} else {
				status("- Failed to disable Calico networking in the v3 configuration (unable to update ClusterInformation)")
			}
			return err
		}
		if ready {
			status("- Successfully enabled Calico networking in the v3 configuration (updated ClusterInformation)")
		} else {
			status("- Successfully disabled Calico networking in the v3 configuration (updated ClusterInformation)")
		}
		return nil
	}

	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
		// ClusterInformation could not be queried.
		if ready {
			status("- Failed to enable Calico networking in the v3 configuration (unable to query ClusterInformation)")
		} else {
			status("- Failed to disable Calico networking in the v3 configuration (unable to query ClusterInformation)")
		}
		return err
	}

	// ClusterInformation does not exist - create a new one.
	c = apiv3.NewClusterInformation()
	c.Name = "default"
	c.Spec.DatastoreReady = &ready
	_, err = clientv3.ClusterInformation().Create(context.Background(), c, options.SetOptions{})
	if err != nil {
		if ready {
			status("- Failed to enable Calico networking in the v3 configuration (unable to create ClusterInformation)")
		} else {
			status("- Failed to disable Calico networking in the v3 configuration (unable to create ClusterInformation)")
		}
		return err
	}
	if ready {
		status("- Successfully enabled Calico networking in the v1 configuration (created ClusterInformation)")
	} else {
		status("- Successfully disabled Calico networking in the v1 configuration (created ClusterInformation)")
	}
	return nil
}

// MigrateData migrates the data from v1 format to v3.  Both a v1 and v3 client are required.
// It returns the converted set of data, *and* an error if the migration failed.
func MigrateData(clientv3 clientv3.Interface, clientv1 upgradeclients.V1ClientInterface) (*ConvertedData, error) {
	// Start by querying and converting all resources.
	status("Performing initial validation of data - no changes will be made")
	res, err := QueryAndConvertResources(clientv1)
	if err != nil {
		return nil, err
	}
	if res.HasErrors() {
		status("- Error converting current v1 snapshot, please run `calico-upgrade validate` to get a detailed report.")
		return nil, errors.New("unable to convert v1 resources to v3")
	}

	// Now set the Ready flag to False.  This will stop Felix from making any data plane updates
	// and will prevent the orchestrator plugins from adding any new workloads or IP allocations
	status("Initial validation of resources was successful")
	if !clientv1.IsKDD() {
		status("Disabling calico networking - this will prevent new calico endpoints from being created but existing endpoints should still be functional")
		if err = SetReadyV1(clientv1, false); err != nil {
			status("Failed to disable calico networking - no changes have been made.  Retry the command.")
			return nil, err
		}

		if oerr := SetReadyV3(clientv3, false); oerr != nil {
			status("Failed to disable calico networking for v3")
			err = Abort(clientv1)
			if err == nil {
				status("Error disabling Calico networking - no changes have been made, re-run the upgrade command.")
				return nil, oerr
			} else {
				status("WARNING: Unable to abort the upgrade - Calico networking is still disabled.  Please either re-run the " +
					"upgrade command, or run `calico-upgrade abort`.")
				return nil, err
			}
		}

	}

	// Pause to allow orchstrators to finish any current allocations.
	status("Calico networking is now disabled - pausing for 15s")
	time.Sleep(15 * time.Second)

	// Now query all the resources again and convert - this is the final snapshot that we will use.
	status("Querying v1 data and converting to v3")
	res, err = QueryAndConvertResources(clientv1)
	status("Data converted")
	status("Storing v3 data")

	// And we also need to migrate the IPAM data.
	migrateIPAMData(clientv3, clientv1)

	return res, err
}

// Abort aborts the upgrade by re-enabling Calico networking in v1.
func Abort(clientv1 upgradeclients.V1ClientInterface) error {
	status("Aborting upgrade")
	var err error
	if !clientv1.IsKDD() {
		status("Re-enabling Calico networking for v1")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = SetReadyV1(clientv1, true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	status("Upgdade aborted successfully")
	return err
}

// migrateIPAMData queries, converts and migrates all of the IPAM data from v1
// to v3 formats.
func migrateIPAMData(clientv3 clientv3.Interface, clientv1 upgradeclients.V1ClientInterface) error {
	var kvpsv3 []*model.KVPair

	// Query all of the IPAM data:
	// -  Blocks
	// -  BlockAffinity
	// -  IPAMHandle
	status("Migrate IPAM data")
	if clientv1.IsKDD() {
		status("-  No IPAM data migration required when using Kubernetes API as the datastore")
		return nil
	}

	// AllocationBlocks need to have their host affinity updated to use the
	// normalized node name.
	status("Convert IPAM allocation blocks")
	kvps, err := clientv1.List(model.BlockListOptions{})
	if err != nil {
		status("-  Failed to list IPAM allocation blocks")
		return err
	}
	for _, kvp := range kvps {
		ab := kvp.Value.(*model.AllocationBlock)
		node := ""
		if ab.Affinity != nil && strings.HasPrefix(*ab.Affinity, "host:") {
			node = strings.TrimPrefix(*ab.Affinity, "host:")
		} else if ab.HostAffinity != nil {
			node = *ab.HostAffinity
		}

		if node != "" {
			aff := "host:" + conversionv1v3.ConvertNodeName(node)
			ab.Affinity = &aff
		}
		kvpsv3 = append(kvpsv3, kvp)
	}

	// BlockAffinities need to have their host updated to use the
	// normalized node name.
	status("Convert IPAM affinity blocks")
	kvps, err = clientv1.List(model.BlockAffinityListOptions{})
	if err != nil {
		status("-  Failed to list IPAM affinity blocks")
		return err
	}
	for _, kvp := range kvps {
		k := kvp.Key.(model.BlockAffinityKey)
		k.Host = conversionv1v3.ConvertNodeName(k.Host)
		kvp.Key = k
		kvpsv3 = append(kvpsv3, kvp)
	}

	// IPAMHandle does not require any conversion.
	status("Migrate IPAM handles")
	kvps, err = clientv1.List(model.IPAMHandleListOptions{})
	if err != nil {
		status("-  Failed to list IPAM handles")
		return err
	}
	kvpsv3 = append(kvpsv3, kvps...)

	// Create/Apply the converted entries into the v3 datastore.
	status("Storing IPAM data in v3 format")
	for _, kvp := range kvps {
		if err := applyToBackend(clientv3, kvp); err != nil {
			status("-  Failed to write IPAM data")
			return err
		}
	}
	status("IPAM data successfully migrated")

	return nil
}

// backend is an interface used to access the backend client from the main clientv3.
type backend interface {
	Backend() bapi.Client
}

// applyToBackend applies the supplied KVPair directly to the backend datastore.
func applyToBackend(clientv3 clientv3.Interface, kvp *model.KVPair) error {
	// Extract the backend API from the v3 client.
	bc := clientv3.(backend).Backend()

	// First try creating the resource.  If the resource already exists, try an update.
	kvp.Revision = ""
	_, err := bc.Create(context.Background(), kvp)
	if err == nil {
		// We created the resource.
		return nil
	}
	if _, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
		for i := 0; i < 5; i++ {
			current, err := bc.Get(context.Background(), kvp.Key, "")
			if err != nil {
				return err
			}

			// Use the obtained KVP for the revision, but update the value with the migrated
			// value.
			kvp.Revision = current.Revision
			_, err = bc.Update(context.Background(), kvp)
			if err == nil {
				// We updated the entry.
				return nil
			}
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); !ok {
				// We hit an error, but not a resource update conflict.  Return the error.
				return err
			}
		}
	}

	return err
}
