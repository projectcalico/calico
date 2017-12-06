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
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_upgrade/pkg/clients"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/upgrade/etcd/conversionv1v3"
	validatorv3 "github.com/projectcalico/libcalico-go/lib/validator/v3"
)

const (
	forceEnableReadyRetries = 30
	maxApplyRetries = 5
	numAppliesPerUpdate = 100
)

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
	ConvertedResourceValidationErrors []ConversionError

	// Name clashes in the converted resources.  These need to be resolved through
	// reconfiguration before attempting the upgrade.
	NameClashes []ConversionError

	// Entries that were skipped because they will be handled by the Kubernetes
	// Policy controller.
	HandledByPolicyCtrl []model.Key
}

func (c *ConvertedData) HasErrors() bool {
	return len(c.ConversionErrors) != 0 ||
		len(c.ConvertedResourceValidationErrors) != 0 ||
		len(c.NameClashes) != 0
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

// Validate validates that the v1 data can be correctly migrated to v3.
func Validate(clientv3 clientv3.Interface, clientv1 upgradeclients.V1ClientInterface) (*ConvertedData, bool) {
	status("Validating conversion of v1 data to v3")
	data, err := queryAndConvertResources(clientv1)
	if err != nil {
		status("Error: unable to perform validation, please resolve errors and retry")
		substatus("Cause: %v", err)
		return nil, false
	}
	if data.HasErrors() {
		status("FAIL: error validating data, check output for details and resolve issues before upgrading")
		return data, false
	}
	substatus("success: data conversion validated")

	status("Validating the v3 datastore")
	if clean, err := v3DatastoreIsClean(clientv3); err != nil {
		status("FAIL: unable to validate the v3 datastore")
		substatus("Cause: %v", err)
	} else if !clean {
		status("FAIL: v3 datastore is not clean.  We recommend that you remove any calico " +
			"data before attempting the upgrade.  If you want to keep the existing v3 data, you may use " +
			"the `--force` flag when running the `start-upgrade` command to force the upgrade, in which " +
			"case the v1 data will be converted and applied over the data that is currently in the v3 " +
			"datastore.")
		substatus("check the output for details of the migrated resources")
		return data, false
	}

	status("SUCCESS: data conversion validated")
	substatus("check the output for details of the migrated resources")
	return data, true
}

// Migrate migrates the data from v1 format to v3.  Both a v1 and v3 client are required.
// It returns the converted set of data, *and* an error if the migration failed.
func Migrate(clientv3 clientv3.Interface, clientv1 upgradeclients.V1ClientInterface, force bool) (*ConvertedData, bool) {
	status("Validating conversion of v1 data to v3")
	data, err := queryAndConvertResources(clientv1)
	if err != nil {
		status("Error: unable to perform validation, please resolve errors and retry")
		substatus("Cause: %v", err)
		return nil, false
	}
	if data.HasErrors() {
		status("FAIL: error validating data, check output for details and resolve issues before upgrading")
		return data, false
	}
	substatus("success: data conversion validated")

	status("Validating the v3 datastore")
	if clean, err := v3DatastoreIsClean(clientv3); err != nil {
		status("FAIL: unable to validate the v3 datastore")
		substatus("Cause: %v", err)
	} else if !clean {
		if force {
			substatus("v3 datastore is dirty, but `--force` flag is set, so continuing with migration")
		} else {
			status("FAIL: v3 datastore is not clean.  We recommend that you remove any calico " +
				"data before attempting the upgrade.  If you want to keep the existing v3 data, you may use " +
				"the `--force` flag when running the `start-upgrade` command to force the upgrade, in which " +
				"case the v1 data will be converted and applied over the data that is currently in the v3 " +
				"datastore.")
			substatus("check the output for details of the migrated resources")
			return data, false
		}
	}
	substatus("success: data conversion validated")

	// Now set the Ready flag to False.  This will stop Felix from making any data plane updates
	// and will prevent the orchestrator plugins from adding any new workloads or IP allocations
	if !clientv1.IsKDD() {
		status("Pausing Calico networking")
		if err = setReadyV1(clientv1, false); err != nil {
			status("FAIL: unable to pause calico networking - no changes have been made.  Retry the command.")
			return nil, false
		}
	}

	// Pause to allow orchestrators to finish any current allocations.
	status("Calico networking is now paused - waiting for 15s")
	time.Sleep(15 * time.Second)

	// Now query all the resources again and convert - this is the final snapshot that we will use.
	status("Querying current v1 snapshot and converting to v3")
	data, err = queryAndConvertResources(clientv1)
	if err != nil {
		 status("FAIL: unable to convert the v1 snapshot to v3 - will attempt to abort upgrade")
		 substatus("cause: %v", err)
		 Abort(clientv1)
		 return nil, false
	}
	substatus("data converted successfully")

	status("Storing v3 data")
	if err = storeV3Resources(clientv3, data); err != nil {
		status("FAIL: unable to store the v3 resources - will attempt to abort upgrade")
		substatus("cause: %v", err)
		Abort(clientv1)
		return nil, false
	}

	// And we also need to migrate the IPAM data.
	if err = migrateIPAMData(clientv3, clientv1); err != nil {
		status("FAIL: unable to migrate the v3 IPAM data - will attempt to abort upgrade")
		substatus("cause: %v", err)
		Abort(clientv1)
		return nil, false
	}

	status("SUCCESS: Migrated data from v1 to v3 datastore")
	substatus("check the output for details of the migrated resources")
	substatus("continue by upgrading your calico/node versions to Calico v3.x")
	return data, true
}

// Abort aborts the upgrade by re-enabling Calico networking in v1.
func Abort(clientv1 upgradeclients.V1ClientInterface) bool {
	status("Aborting upgrade")
	var err error
	if !clientv1.IsKDD() {
		status("Re-enabling Calico networking for v1")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = setReadyV1(clientv1, true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		status("FAIL: failed to abort upgrade.  Retry command.")
		substatus("cause: %v", err)
		return false
	}
	status("SUCCESS: upgdade aborted")
	return true
}


// Complete completes the upgrade by re-enabling Calico networking in v1.
func Complete(clientv1 upgradeclients.V1ClientInterface) error {
	status("Completing upgrade")
	var err error
	if !clientv1.IsKDD() {
		status("Re-enabling Calico networking for v1")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = setReadyV1(clientv1, true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	status("Upgrade completed successfully")
	return err
}

type policyCtrlFilterOut func(model.Key) bool
var noFilter = func(_ model.Key) bool { return false }

type ic interface {
	IsClean() (bool, error)
}

func v3DatastoreIsClean(clientv3 clientv3.Interface) (bool, error) {
	if i, ok := clientv3.(ic); ok {
		return i.IsClean()
	}
	return true, nil
}

// queryAndConvertResources queries the v1 resources and converts them to the equivalent
// v3 resources.
// This method returns an error if it is unable to query the current v1 settings.
// Errors from the conversion are returned within the ConvertedData - this function will
// attempt to convert everything before returning with the set of converted data and
// conversion errors - this allows a full pre-migration report to be generated in a single
// shot.
func queryAndConvertResources(clientv1 upgradeclients.V1ClientInterface) (*ConvertedData, error) {
	res := &ConvertedData{}

	substatus("handling global FelixConfiguration")
	// Query and convert global felix configuration and cluster info.
	fc := &felixConfig{}
	if err := fc.queryAndConvertFelixConfigV1ToV3(clientv1, res); err != nil {
		return nil, err
	}

	substatus("handling global BGPConfiguration")
	// Query the global BGP configuration:  default AS number; node-to-node mesh.
	if err := queryAndConvertGlobalBGPConfigV1ToV3(clientv1, res); err != nil {
		return nil, err
	}

	substatus("handling global BGPPeer configuration")
	// Query and convert the BGPPeers
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.GlobalBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}
	substatus("handling node specific BGPPeer configuration")
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.NodeBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling HostEndpoint configuration")
	// Query and convert the HostEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.HostEndpointListOptions{}, conversionv1v3.HostEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling IPPool configuration")
	// Query and convert the IPPools
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.IPPoolListOptions{}, conversionv1v3.IPPool{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling Node configuration")
	// Query and convert the Nodes
	if err := queryAndConvertV1ToV3Nodes(clientv1, res); err != nil {
		return nil, err
	}

	substatus("handling GlobalNetworkPolicy configuration")
	// Query and convert the Policies
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.PolicyListOptions{}, conversionv1v3.Policy{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling Profile configuration")
	// Query and convert the Profiles
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.ProfileListOptions{}, conversionv1v3.Profile{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling WorkloadEndpoint configuration")
	// Query and convert the WorkloadEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, res,
		model.WorkloadEndpointListOptions{}, conversionv1v3.WorkloadEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	return res, nil
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
			res.ConvertedResourceValidationErrors = append(res.ConvertedResourceValidationErrors, ConversionError{
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

func queryAndConvertGlobalBGPConfigV1ToV3(clientv1 upgradeclients.V1ClientInterface, res *ConvertedData) error {
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

func status(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if displayStatus {
		fmt.Println(msg)
	}
}
func substatus(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if displayStatus {
		fmt.Println("-  " + msg)
	}
}

func setReadyV1(clientv1 upgradeclients.V1ClientInterface, ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v1")
	_, err := clientv1.Apply(&model.KVPair{
		Key:   model.ReadyFlagKey{},
		Value: ready,
	})
	if err != nil {
		if ready {
			substatus("failed to enable Calico networking in the v1 configuration")
		} else {
			substatus("failed to disable Calico networking in the v1 configuration")
		}
	}
	if ready {
		substatus("successfully enabled Calico networking in the v1 configuration")
	} else {
		substatus("successfully disabled Calico networking in the v1 configuration")
	}
	return nil
}

func setReadyV3(clientv3 clientv3.Interface, ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v3")
	c, err := clientv3.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// ClusterInformation already exists - update the settings.
		log.WithField("Ready", ready).Info("Updating Ready flag in v3 ClusterInformation")
		c.Spec.DatastoreReady = &ready
		_, err = clientv3.ClusterInformation().Update(context.Background(), c, options.SetOptions{})
		if err != nil {
			if ready {
				substatus("failed to enable Calico networking in the v3 configuration (unable to update ClusterInformation)")
			} else {
				substatus("failed to disable Calico networking in the v3 configuration (unable to update ClusterInformation)")
			}
			return err
		}
		if ready {
			substatus("successfully enabled Calico networking in the v3 configuration (updated ClusterInformation)")
		} else {
			substatus("successfully disabled Calico networking in the v3 configuration (updated ClusterInformation)")
		}
		return nil
	}

	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
		// ClusterInformation could not be queried.
		if ready {
			substatus("failed to enable Calico networking in the v3 configuration (unable to query ClusterInformation)")
		} else {
			substatus("failed to disable Calico networking in the v3 configuration (unable to query ClusterInformation)")
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
			substatus("failed to enable Calico networking in the v3 configuration (unable to create ClusterInformation)")
		} else {
			substatus("failed to disable Calico networking in the v3 configuration (unable to create ClusterInformation)")
		}
		return err
	}
	if ready {
		substatus("successfully enabled Calico networking in the v1 configuration (created ClusterInformation)")
	} else {
		substatus("successfully disabled Calico networking in the v1 configuration (created ClusterInformation)")
	}
	return nil
}

// storeV3Resources stores the converted resources in the v3 datastore.
func storeV3Resources(clientv3 clientv3.Interface, data *ConvertedData) error {
	status("Storing resources in v3 format")
	for n, r := range data.Resources {
		// Convert the resource to a KVPair and access the backend datastore directly.
		// This is slightly more efficient, and cuts out some of the unneccessary additional
		// processing.
		if err := applyToBackend(clientv3, &model.KVPair{
			Key: model.ResourceKey{
				Kind: r.GetObjectKind().GroupVersionKind().Kind,
				Name: r.GetObjectMeta().GetName(),
				Namespace: r.GetObjectMeta().GetNamespace(),
			},
			Value: r,
		}); err != nil {
			return err
		}

		if (n+1) % numAppliesPerUpdate == 0 {
			substatus("applied %d resources", (n+1))
		}
	}
	substatus("success: resources stored in v3 datastore")
	return nil
}

// migrateIPAMData queries, converts and migrates all of the IPAM data from v1
// to v3 formats.
func migrateIPAMData(clientv3 clientv3.Interface, clientv1 upgradeclients.V1ClientInterface) error {
	var kvpsv3 []*model.KVPair

	// Query all of the IPAM data:
	// -  Blocks
	// -  BlockAffinity
	// -  IPAMHandle
	status("Migrating IPAM data")
	if clientv1.IsKDD() {
		substatus("no IPAM data migration required when using Kubernetes API as the datastore")
		return nil
	}

	// AllocationBlocks need to have their host affinity updated to use the
	// normalized node name.
	substatus("listing and converting IPAM allocation blocks")
	kvps, err := clientv1.List(model.BlockListOptions{})
	if err != nil {
		status("FAIL: unable to list IPAM allocation blocks")
		substatus("cause: %v", err)
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
	substatus("listing and converting IPAM affinity blocks")
	kvps, err = clientv1.List(model.BlockAffinityListOptions{})
	if err != nil {
		status("FAIL: unable to list IPAM affinity blocks")
		substatus("cause: %v", err)
		return err
	}
	for _, kvp := range kvps {
		k := kvp.Key.(model.BlockAffinityKey)
		k.Host = conversionv1v3.ConvertNodeName(k.Host)
		kvp.Key = k
		kvpsv3 = append(kvpsv3, kvp)
	}

	// IPAMHandle does not require any conversion.
	substatus("listing IPAM handles")
	kvps, err = clientv1.List(model.IPAMHandleListOptions{})
	if err != nil {
		status("FAIL: unable to list IPAM handles")
		substatus("cause: %v", err)
		return err
	}
	kvpsv3 = append(kvpsv3, kvps...)

	// Create/Apply the converted entries into the v3 datastore.
	substatus("storing IPAM data in v3 format")
	for _, kvp := range kvps {
		if err := applyToBackend(clientv3, kvp); err != nil {
			status("FAIL: error writing IPAM data to v3 datastore")
			return err
		}
	}

	// We migrated the data successfully.
	substatus("success: IPAM data migrated")
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
	logCxt := log.WithField("Key", kvp.Key)
	logCxt.Debug("Attempting to create resource")
	kvp.Revision = ""
	_, err := bc.Create(context.Background(), kvp)
	if err == nil {
		logCxt.Debug("Resource created")
		return nil
	}
	if _, ok := err.(cerrors.ErrorResourceAlreadyExists); ok {
		logCxt.Debug("Resource already exists, try update")
		for i := 0; i < maxApplyRetries; i++ {
			// Query the current settings and update the kvp revision so that we can
			// perform an update.
			logCxt.Debug("Attempting to update resource")
			current, err := bc.Get(context.Background(), kvp.Key, "")
			if err != nil {
				return err
			}
			kvp.Revision = current.Revision

			_, err = bc.Update(context.Background(), kvp)
			if err == nil {
				logCxt.Debug("Resource updated")
				return nil
			}
			if _, ok := err.(cerrors.ErrorResourceUpdateConflict); !ok {
				break
			}
		}
	}

	logCxt.WithError(err).Info("Failed to create or update resource")
	return err
}
