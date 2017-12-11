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
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

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
	maxApplyRetries         = 5
	numAppliesPerUpdate     = 100
)

// DisplayStatusMessages is used to set whether the migration code should
// output status messages to stdout and logs (true), or just log (false).
var displayStatus = false

func DisplayStatusMessages(d bool) {
	displayStatus = d
}

// Interactive is used to set whether the migration code should be interactive
// (true) or not. If interactive, the script will explicitly request the user
// to verify certain actions.
var interactive = false

func Interactive(i bool) {
	interactive = i
}

type Result int

const (
	ResultOK Result = iota
	ResultFail
	ResultFailNeedsAbort
	ResultFailNeedsRetry
)

type ConvertedData struct {
	// The converted resources
	Resources []conversionv1v3.Resource

	// The converted resource names
	NameConversions []NameConversion

	// Errors hit attempting to convert the v1 data to v3 format. The
	// KeyV3 and ValueV3 will be nil for these conversion errors.
	ConversionErrors []ConversionError

	// Errors hit validating the converted v3 data. This suggests an error in the
	// conversion script which should be fixed before reattempting the conversion.
	ConvertedResourceValidationErrors []ConversionError

	// Name clashes in the converted resources. These need to be resolved through
	// reconfiguration before attempting the upgrade.
	NameClashes []NameClash

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
	Cause   error
	KeyV1   model.Key
	ValueV1 interface{}
	KeyV3   model.Key
	ValueV3 conversionv1v3.Resource
}

// Details about name/id conversions.
type NameConversion struct {
	KeyV1 model.Key
	KeyV3 model.Key
}

// Details about name/id conversions.
type NameClash struct {
	KeyV1      model.Key
	KeyV3      model.Key
	OtherKeyV1 model.Key
}

// Validate validates that the v1 data can be correctly migrated to v3.
func Validate(clientv3 clientv3.Interface, clientv1 clients.V1ClientInterface, ignoreV3Data bool) (*ConvertedData, Result) {
	status("Validating conversion of v1 data to v3")
	data, err := queryAndConvertResources(clientv1)
	if err != nil {
		errorstatus("Unable to perform validation, please resolve errors and retry")
		substatus("Cause: %v", err)
		return nil, ResultFail
	}
	if data.HasErrors() {
		errorstatus("Error converting data, check output for details and resolve issues before starting upgrade")
		return data, ResultFail
	}
	substatus("data conversion successful")

	status("Validating the v3 datastore")
	if clean, err := v3DatastoreIsClean(clientv3); err != nil {
		errorstatus("Unable to validate the v3 datastore")
		substatus("Cause: %v", err)
		return data, ResultFail
	} else if !clean {
		if ignoreV3Data {
			substatus("v3 datastore is dirty, but '--ignore-v3-data' flag is set, so continuing with migration")
		} else {
			errorstatus("The v3 datastore is not clean. We recommend that you remove any calico " +
				"data before attempting the upgrade. If you want to keep the existing v3 data, you may use " +
				"the '--ignore-v3-data' flag when running the 'start-upgrade' command to force the upgrade, in which " +
				"case the v1 data will be converted and will overwrite matching entries in the v3 datastore.")
			substatus("check the output for details of the migrated resources")
			return data, ResultFail
		}
	} else {
		substatus("datastore is clean")
	}

	// Finally, check that we found some data.  Note: if there was no v1 data then
	// fail the script.
	if len(data.Resources) == 0 {
		errorstatus("No v1 resources detected: is the API configuration correctly configured?")
		return nil, ResultFail
	}

	// Everything validated correctly.
	status("Pre-upgrade validation successful")
	return data, ResultOK
}

// Migrate migrates the data from v1 format to v3. Both a v1 and v3 client are required.
// It returns the converted set of data, a bool indicating whether the migration succeeded.
func Migrate(clientv3 clientv3.Interface, clientv1 clients.V1ClientInterface, ignoreV3Data bool) (*ConvertedData, Result) {
	// Start by validating the conversion.
	data, rc := Validate(clientv3, clientv1, ignoreV3Data)
	if rc != ResultOK {
		return data, rc
	}

	// Now set the Ready flag to False. This will stop Felix from making any data plane updates
	// and will prevent the orchestrator plugins from adding any new workloads or IP allocations
	if !clientv1.IsKDD() {
		if interactive {
			status("\nYou are about to start the migration of Calico v1 data format to " +
				"Calico v3 data format. During this time and until the upgrade is completed " +
				"Calico networking will be paused - which means no new Calico networked " +
				"endpoints can be created.\n")
			// Use printf for the prompt so that we don't insert a newline.
			fmt.Printf("Type yes to proceed (any other input cancels): ")
			var input string
			fmt.Scanln(&input)
			if strings.ToLower(strings.TrimSpace(input)) != "yes" {
				fmt.Println("User cancelled. Exiting.")
				os.Exit(1)
			}
		}

		status("Pausing Calico networking")
		if err := setReadyV1(clientv1, false); err != nil {
			errorstatus("Unable to pause calico networking - no changes have been made. Retry the command.")
			return nil, ResultFailNeedsRetry
		}
	}

	// Pause to allow orchestrators to finish any current allocations.
	status("Calico networking is now paused - waiting for 15s")
	time.Sleep(15 * time.Second)

	// Now query all the resources again and convert - this is the final snapshot that we will use.
	status("Querying current v1 snapshot and converting to v3")
	data, err := queryAndConvertResources(clientv1)
	if err != nil {
		errorstatus("Unable to convert the v1 snapshot to v3 - will attempt to abort upgrade")
		substatus("cause: %v", err)
		r := Abort(clientv1)
		if r == ResultOK {
			return nil, ResultFail
		}
		return nil, ResultFailNeedsAbort
	}
	if data.HasErrors() {
		errorstatus("Error validating data - will attempt to abort upgrade")
		r := Abort(clientv1)
		if r == ResultOK {
			return nil, ResultFail
		}
		return data, ResultFailNeedsAbort
	}
	substatus("data converted successfully")

	status("Storing v3 data")
	if err = storeV3Resources(clientv3, data); err != nil {
		errorstatus("Unable to store the v3 resources - will attempt to abort upgrade")
		substatus("cause: %v", err)
		r := Abort(clientv1)
		if r == ResultOK {
			return nil, ResultFail
		}
		return nil, ResultFailNeedsAbort
	}

	// And we also need to migrate the IPAM data.
	if err = migrateIPAMData(clientv3, clientv1); err != nil {
		errorstatus("Unable to migrate the v3 IPAM data - will attempt to abort upgrade")
		substatus("cause: %v", err)
		r := Abort(clientv1)
		if r == ResultOK {
			return nil, ResultFail
		}
		return nil, ResultFailNeedsAbort
	}

	status("Data migration from v1 to v3 successful")
	substatus("check the output for details of the migrated resources")
	substatus("continue by upgrading your calico/node versions to Calico v3.x")
	return data, ResultOK
}

// Abort aborts the upgrade by re-enabling Calico networking in v1.
func Abort(clientv1 clients.V1ClientInterface) Result {
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
		errorstatus("Failed to abort upgrade. Retry command.")
		substatus("cause: %v", err)
		return ResultFailNeedsAbort
	}
	status("Upgrade aborted successfully")
	return ResultOK
}

// Complete completes the upgrade by re-enabling Calico networking in v1.
func Complete(clientv3 clientv3.Interface, clientv1 clients.V1ClientInterface) Result {
	if interactive {
		fmt.Print("\nYou are about to complete the upgrade process to Calico v3.\n" +
			"At this point, the v1 format data should have been successfully converted\n" +
			"to v3 format, and all calico/node instances and orchestrator plugins\n" +
			"(e.g. CNI) should be running Calico v3.\n\n" +
			"Type yes to proceed (any other input cancels): ")
		var input string
		fmt.Scanln(&input)
		if strings.ToLower(strings.TrimSpace(input)) != "yes" {
			fmt.Println("User cancelled. Exiting.")
			os.Exit(1)
		}
	}

	status("Completing upgrade")
	var err error
	if !clientv1.IsKDD() {
		status("Enabling Calico networking for v3")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = setReadyV3(clientv3, true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		errorstatus("Failed to complete upgrade. Retry command.")
		substatus("cause: %v", err)
		return ResultFailNeedsRetry
	}
	status("Upgrade completed successfully")
	return ResultOK
}

type policyCtrlFilterOut func(model.Key) bool

var noFilter = func(_ model.Key) bool { return false }

// Filter to filter out K8s backed network policies
var filterGNP = func(k model.Key) bool {
	gk := k.(model.PolicyKey)
	return strings.HasPrefix(gk.Name, "knp.default.")
}

// Filter to filter out K8s (namespace) backed profiles
var filterProfile = func(k model.Key) bool {
	gk := k.(model.ProfileKey)
	return strings.HasPrefix(gk.Name, "k8s_ns.")
}

type ic interface {
	IsClean() (bool, error)
}

func v3DatastoreIsClean(clientv3 clientv3.Interface) (bool, error) {
	bc := clientv3.(backend).Backend()
	if i, ok := bc.(ic); ok {
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
func queryAndConvertResources(clientv1 clients.V1ClientInterface) (*ConvertedData, error) {
	data := &ConvertedData{}

	substatus("handling FelixConfiguration (global) resource")
	// Query and convert global felix configuration and cluster info.
	fc := &felixConfig{}
	if err := fc.queryAndConvertFelixConfigV1ToV3(clientv1, data); err != nil {
		return nil, err
	}

	substatus("handling BGPConfiguration (global) resource")
	// Query the global BGP configuration:  default AS number; node-to-node mesh.
	if err := queryAndConvertGlobalBGPConfigV1ToV3(clientv1, data); err != nil {
		return nil, err
	}

	substatus("handling BGPPeer (global) resources")
	// Query and convert the BGPPeers
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.GlobalBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}
	substatus("handling BGPPeer (node) resources")
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.NodeBGPPeerListOptions{}, conversionv1v3.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling HostEndpoint resources")
	// Query and convert the HostEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.HostEndpointListOptions{}, conversionv1v3.HostEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling IPPool resources")
	// Query and convert the IPPools
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.IPPoolListOptions{}, conversionv1v3.IPPool{}, noFilter,
	); err != nil {
		return nil, err
	}

	substatus("handling Node resources")
	// Query and convert the Nodes
	if err := queryAndConvertV1ToV3Nodes(clientv1, data); err != nil {
		return nil, err
	}

	substatus("handling GlobalNetworkPolicy resources")
	// Query and convert the Policies
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.PolicyListOptions{}, conversionv1v3.Policy{}, filterGNP,
	); err != nil {
		return nil, err
	}

	substatus("handling Profile resources")
	// Query and convert the Profiles
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.ProfileListOptions{}, conversionv1v3.Profile{}, filterProfile,
	); err != nil {
		return nil, err
	}

	substatus("handling WorkloadEndpoint resources")
	// Query and convert the WorkloadEndpoints
	if err := queryAndConvertV1ToV3Resources(
		clientv1, data,
		model.WorkloadEndpointListOptions{}, conversionv1v3.WorkloadEndpoint{}, noFilter,
	); err != nil {
		return nil, err
	}

	return data, nil
}

// Query the v1 format resources and convert to the v3 format. Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func queryAndConvertV1ToV3Resources(
	clientv1 clients.V1ClientInterface,
	data *ConvertedData,
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
	// name clashes. We don't generally expect this, but we do need to police against
	// it just in case.
	convertedNames := make(map[string]model.Key, len(kvps))

	// Pass the results through the supplied converter and check that each result
	// validates.
	for _, kvp := range kvps {
		if filterOut(kvp.Key) {
			log.Infof("Filter out Policy Controller created resource: %s", kvp.Key)
			data.HandledByPolicyCtrl = append(data.HandledByPolicyCtrl, kvp.Key)
		}

		r, err := converter.BackendV1ToAPIV3(kvp)
		if err != nil {
			data.ConversionErrors = append(data.ConversionErrors, ConversionError{
				KeyV1:   kvp.Key,
				ValueV1: kvp.Value,
				Cause:   err,
			})
			continue
		}

		// Check the converted name for clashes. Store an error if there is a clash and
		// continue with additional checks so that we output as much information as possible.
		valid := true
		convertedName := r.GetObjectMeta().GetNamespace() + "/" + r.GetObjectMeta().GetName()
		if k, ok := convertedNames[convertedName]; ok {
			data.NameClashes = append(data.NameClashes, NameClash{
				KeyV1:      kvp.Key,
				KeyV3:      resourceToKey(r),
				OtherKeyV1: k,
			})
			valid = false
		}
		convertedNames[convertedName] = kvp.Key

		// Check the converted resource validates correctly.
		if err := validatorv3.Validate(r); err != nil {
			data.ConvertedResourceValidationErrors = append(data.ConvertedResourceValidationErrors, ConversionError{
				KeyV1:   kvp.Key,
				ValueV1: kvp.Value,
				KeyV3:   resourceToKey(r),
				ValueV3: r,
				Cause:   err,
			})
			valid = false
		}

		// Only store the resource and the converted name if it's valid.
		if valid {
			data.Resources = append(data.Resources, r)
			data.NameConversions = append(data.NameConversions, NameConversion{
				KeyV1: kvp.Key,
				KeyV3: resourceToKey(r),
			})
		}
	}

	return nil
}

func queryAndConvertGlobalBGPConfigV1ToV3(clientv1 clients.V1ClientInterface, res *ConvertedData) error {
	globalBGPConfig := apiv3.NewBGPConfiguration()
	globalBGPConfig.Name = "default"

	log.Info("Converting BGP config -> BGPConfiguration(default)")
	var setValue bool
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
				ValueV1: kvp.Value,
				Cause:   fmt.Errorf("default ASNumber is not valid: %s", kvp.Value.(string)),
			})
			return err
		}
		globalBGPConfig.Spec.ASNumber = &asNum
		setValue = true
	}

	if kvp, err := clientv1.Get(model.GlobalBGPConfigKey{Name: "LogLevel"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global BGP log level configured")
	} else if kvp.Value.(string) != "" {
		globalBGPConfig.Spec.LogSeverityScreen = convertLogLevel(kvp.Value.(string))
		setValue = true
	}

	if kvp, err := clientv1.Get(model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global node to node mesh enabled setting configured")
	} else if kvp.Value.(string) != "" {
		nodeMeshEnabled := strings.ToLower(kvp.Value.(string)) == "true"
		globalBGPConfig.Spec.NodeToNodeMeshEnabled = &nodeMeshEnabled
		setValue = true
	}
	if setValue {
		res.Resources = append(res.Resources, globalBGPConfig)
	}
	return nil
}

// Query the v1 format resources and convert to the v3 format. Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func queryAndConvertV1ToV3Nodes(
	v1Client clients.V1ClientInterface,
	data *ConvertedData,
) error {
	// Start by querying the nodes and converting them, we don't add the nodes to the list
	// of results just yet.
	var nodes []conversionv1v3.Resource
	err := queryAndConvertV1ToV3Resources(
		v1Client, data,
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
	data.Resources = append(data.Resources, nodes...)

	return nil
}

// convertLogLevel converts the v1 log level to the equivalent v3 log level. We
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

// Display a 79-char word wrapped error message.
func errorstatus(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Error(strings.TrimSpace(msg))
	if displayStatus {
		lines := wordWrap("ERROR: "+msg, 79)
		for _, line := range lines {
			fmt.Println(line)
		}
	}
}

// Display a 79-char word wrapped status message.
func status(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if displayStatus {
		lines := wordWrap(msg, 79)
		for _, line := range lines {
			fmt.Println(line)
		}
	}
}

// Display a 79-char word wrapped sub status (a bulleted message).
func substatus(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if displayStatus {
		lines := wordWrap(msg, 76)
		fmt.Println("-  " + lines[0])
		for _, line := range lines[1:] {
			fmt.Println("   " + line)
		}
	}
}

// setReadyV1 sets the ready flag in the v1 datastore.
func setReadyV1(clientv1 clients.V1ClientInterface, ready bool) error {
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

// setReadyV1 sets the ready flag in the v3 datastore.
func setReadyV3(clientv3 clientv3.Interface, ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v3")
	c, err := clientv3.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// ClusterInformation already exists - update the settings.
		log.WithField("Ready", ready).Info("Updating Ready flag in v3 ClusterInformation")
		c.Spec.DatastoreReady = &ready
		_, err = clientv3.ClusterInformation().Update(context.Background(), c, options.SetOptions{})
		if err != nil {
			log.WithError(err).Info("Hit error setting ready flag in v3 ClusterInformation")
			if ready {
				substatus("failed to enable Calico networking in the v3 configuration: %v", err)
			} else {
				substatus("failed to disable Calico networking in the v3 configuration: %v", err)
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

// resourceToKey creates a model.Key from a v3 resource.
func resourceToKey(r conversionv1v3.Resource) model.Key {
	return model.ResourceKey{
		Kind:      r.GetObjectKind().GroupVersionKind().Kind,
		Name:      r.GetObjectMeta().GetName(),
		Namespace: r.GetObjectMeta().GetNamespace(),
	}
}

// storeV3Resources stores the converted resources in the v3 datastore.
func storeV3Resources(clientv3 clientv3.Interface, data *ConvertedData) error {
	status("Storing resources in v3 format")
	for n, r := range data.Resources {
		// Convert the resource to a KVPair and access the backend datastore directly.
		// This is slightly more efficient, and cuts out some of the unneccessary additional
		// processing. Since we applying directly to the backend we need to set the UUID
		// and creation timestamp which is normally handled by clientv3.
		r.GetObjectMeta().SetCreationTimestamp(metav1.Now())
		r.GetObjectMeta().SetUID(uuid.NewUUID())
		if err := applyToBackend(clientv3, &model.KVPair{
			Key:   resourceToKey(r),
			Value: r,
		}); err != nil {
			return err
		}

		if (n+1)%numAppliesPerUpdate == 0 {
			substatus("applied %d resources", (n + 1))
		}
	}
	substatus("success: resources stored in v3 datastore")
	return nil
}

// migrateIPAMData queries, converts and migrates all of the IPAM data from v1
// to v3 formats.
func migrateIPAMData(clientv3 clientv3.Interface, clientv1 clients.V1ClientInterface) error {
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
		errorstatus("Unable to list IPAM allocation blocks")
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
		errorstatus("Unable to list IPAM affinity blocks")
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
		errorstatus("Unable to list IPAM handles")
		substatus("cause: %v", err)
		return err
	}
	kvpsv3 = append(kvpsv3, kvps...)

	// Create/Apply the converted entries into the v3 datastore.
	substatus("storing IPAM data in v3 format")
	for _, kvp := range kvps {
		if err := applyToBackend(clientv3, kvp); err != nil {
			errorstatus("Error writing IPAM data to v3 datastore")
			return err
		}
	}

	// We migrated the data successfully.
	substatus("IPAM data migrated successfully")
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

	// First try creating the resource. If the resource already exists, try an update.
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

// wordWrap wraps a long string at the specified max length. The text may
// contain newlines.
func wordWrap(text string, length int) []string {
	// First split by newlines. We want to honor existing newlines.
	var lines []string
	parts := strings.Split(text, "\n")
	for _, part := range parts {
		lines = append(lines, wordWrapPart(part, length)...)
	}
	return lines
}

// wordWrapPart wraps a long string at the specified max length. Newlines
// are treated as whitespace.
func wordWrapPart(text string, length int) []string {
	// First split by newlines. We want to honor existing newlines.
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{}
	}

	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > length {
			lines = append(lines, line)
			line = word
		} else {
			line += " " + word
		}
	}
	lines = append(lines, line)

	return lines
}
