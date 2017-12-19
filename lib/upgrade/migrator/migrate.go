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

package migrator

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/coreos/go-semver/semver"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"errors"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/upgrade/converters"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients"
	validatorv3 "github.com/projectcalico/libcalico-go/lib/validator/v3"
)

const (
	forceEnableReadyRetries = 30
	maxApplyRetries         = 5
	numAppliesPerUpdate     = 100
	retryInterval           = 5 * time.Second
)

// Interface is the migration interface used for migrating data from version
// v2.x to v3.x.
type Interface interface {
	ValidateConversion() (*MigrationData, error)
	IsDestinationEmpty() (bool, error)
	ShouldMigrate() (bool, error)
	Migrate() (*MigrationData, error)
	Abort() error
	Complete() error
}

// StatusWriterInterface is an optional interface supplied by the consumer of
// the migration helper used to record status of the migration.
type StatusWriterInterface interface {
	Msg(string)
	Bullet(string)
	Error(string)
}

// New creates a new migration helper implementing Interface.
func New(clientv3 clientv3.Interface, clientv1 clients.V1ClientInterface, statusWriter StatusWriterInterface) Interface {
	return &migrationHelper{
		clientv3:     clientv3,
		clientv1:     clientv1,
		statusWriter: statusWriter,
	}
}

// migrationHelper implements the migrate.Interface.
type migrationHelper struct {
	clientv3                clientv3.Interface
	clientv1                clients.V1ClientInterface
	enforceEmptyDestination bool
	statusWriter            StatusWriterInterface
}

// Error types encountered during validation and migration.
type ErrorType int

const (
	ErrorGeneric ErrorType = iota
	ErrorConvertingData
	ErrorMigratingData
)

type MigrationError struct {
	Err        error
	Type       ErrorType
	NeedsAbort bool
}

func (m MigrationError) Error() string {
	return m.Err.Error()
}

// MigrationData includes details about data migrated using the migration helper.
type MigrationData struct {
	// The converted resources
	Resources []converters.Resource

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

// HasErrors returns whether there are any errors contained in the MigrationData.
func (c *MigrationData) HasErrors() bool {
	return len(c.ConversionErrors) != 0 ||
		len(c.ConvertedResourceValidationErrors) != 0 ||
		len(c.NameClashes) != 0
}

// ConversionError contains details about a specific error converting a
// v1 resource to a v3 resource.
type ConversionError struct {
	Cause   error
	KeyV1   model.Key
	ValueV1 interface{}
	KeyV3   model.Key
	ValueV3 converters.Resource
}

// NameConversion contains details about name/id conversions.
type NameConversion struct {
	KeyV1 model.Key
	KeyV3 model.Key
}

// NameClash contains details about name/id clashes (i.e. when two converted resource
// names (for the same resource type) clash.
type NameClash struct {
	KeyV1      model.Key
	KeyV3      model.Key
	OtherKeyV1 model.Key
}

// Validate validates that the v1 data can be correctly converted to v3.
// If an error is returned it will be of type MigrationError.
func (m *migrationHelper) ValidateConversion() (*MigrationData, error) {
	m.status("Validating conversion of v1 data to v3")
	data, err := m.queryAndConvertResources()
	if err != nil {
		m.statusError("Unable to perform validation, please resolve errors and retry")
		m.statusBullet("Cause: %v", err)
		return nil, MigrationError{
			Type: ErrorGeneric,
			Err:  err,
		}
	}
	if data.HasErrors() {
		m.statusError("Error converting data, check output for details and resolve issues before starting upgrade")
		return data, MigrationError{
			Type: ErrorConvertingData,
			Err:  fmt.Errorf("error converting data: %v", err),
		}
	}
	m.statusBullet("data conversion successful")

	// Finally, check that we found some data. For KDD if there were no resources
	// then that's fine, otherwise we should fail.
	if !m.clientv1.IsKDD() && len(data.Resources) == 0 {
		m.statusError("No v1 resources detected: is the API configuration correctly configured?")
		return nil, MigrationError{
			Type: ErrorGeneric,
			Err:  errors.New("no v1 resources detected: is the API configuration correctly configured?"),
		}
	}

	// Everything validated correctly.
	m.status("Data conversion validated successfully")
	return data, nil
}

func (m *migrationHelper) IsDestinationEmpty() (bool, error) {
	m.status("Validating the v3 datastore")
	clean, err := m.v3DatastoreIsClean()
	if err != nil {
		m.statusError("Unable to validate the v3 datastore")
		m.statusBullet("Cause: %v", err)
		return false, MigrationError{
			Type: ErrorGeneric,
			Err:  fmt.Errorf("unable to validate the v3 datastore: %v", err),
		}
	}
	if clean {
		m.statusBullet("the v3 datastore is empty")
	} else {
		m.statusBullet("the v3 datastore is not empty")
	}
	return clean, nil
}

// Migrate migrates the data from v1 format to v3. Both a v1 and v3 client are required.
// It returns the converted set of data, a bool indicating whether the migration succeeded.
// If an error is returned it will be of type MigrationError.
func (m *migrationHelper) Migrate() (*MigrationData, error) {
	// Now set the Ready flag to False. This will stop Felix from making any data plane updates
	// and will prevent the orchestrator plugins from adding any new workloads or IP allocations
	if !m.clientv1.IsKDD() {
		m.status("Pausing Calico networking")
		if err := m.setReadyV1(false); err != nil {
			m.statusError("Unable to pause calico networking")
			return nil, MigrationError{
				Type: ErrorGeneric,
				Err:  fmt.Errorf("unable to pause calico networking: %v", err),
			}
		}

		// Wait for a short period to allow orchestrators to finish any current allocations.
		m.status("Calico networking is now paused - waiting for 15s")
		time.Sleep(15 * time.Second)
	}

	// Now query all the resources again and convert - this is the final snapshot that we will use.
	m.status("Querying current v1 snapshot and converting to v3")
	data, err := m.queryAndConvertResources()
	if err != nil {
		m.statusError("Unable to convert the v1 snapshot to v3")
		m.statusBullet("cause: %v", err)
		return nil, m.abortAfterError(
			fmt.Errorf("error converting data: %v", err), ErrorGeneric,
		)
	}
	if data.HasErrors() {
		m.statusError("Error converting data - will attempt to abort upgrade")
		return nil, m.abortAfterError(
			fmt.Errorf("error converting data: %v", err), ErrorConvertingData,
		)
	}
	m.statusBullet("data converted successfully")

	m.status("Storing v3 data")
	if err = m.storeV3Resources(data); err != nil {
		m.statusError("Unable to store the v3 resources")
		m.statusBullet("cause: %v", err)
		return nil, m.abortAfterError(
			fmt.Errorf("error storing converted data: %v", err), ErrorMigratingData,
		)
	}

	// And we also need to migrate the IPAM data.
	m.status("Migrating IPAM data")
	if m.clientv1.IsKDD() {
		m.statusBullet("no data to migrate - not supported")
	} else if err = m.migrateIPAMData(); err != nil {
		m.statusError("Unable to migrate the v3 IPAM data")
		m.statusBullet("cause: %v", err)
		return nil, m.abortAfterError(
			fmt.Errorf("error migrating IPAM data: %v", err), ErrorMigratingData,
		)
	}

	m.status("Data migration from v1 to v3 successful")
	m.statusBullet("check the output for details of the migrated resources")
	m.statusBullet("continue by upgrading your calico/node versions to Calico v3.x")
	return data, nil
}

func (m *migrationHelper) abortAfterError(err error, errType ErrorType) error {
	if m.clientv1.IsKDD() {
		return MigrationError{Type: errType, Err: err}
	}
	if ae := m.Abort(); ae == nil {
		return MigrationError{Type: errType, Err: err}
	}
	return MigrationError{Type: errType, Err: err, NeedsAbort: true}
}

// Abort aborts the upgrade by re-enabling Calico networking in v1.
// If an error is returned it will be of type MigrationError.
func (m *migrationHelper) Abort() error {
	m.status("Aborting upgrade")
	var err error
	if !m.clientv1.IsKDD() {
		m.status("Re-enabling Calico networking for v1")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = m.setReadyV1(true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		m.statusError("Failed to abort upgrade. Retry command.")
		m.statusBullet("cause: %v", err)
		return MigrationError{Type: ErrorGeneric, Err: err, NeedsAbort: true}
	}
	m.status("Upgrade aborted successfully")
	return nil
}

// Complete completes the upgrade by re-enabling Calico networking in v1.
// If an error is returned it will be of type MigrationError.
func (m *migrationHelper) Complete() error {
	m.status("Completing upgrade")
	var err error
	if !m.clientv1.IsKDD() {
		m.status("Enabling Calico networking for v3")
		for i := 0; i < forceEnableReadyRetries; i++ {
			err = m.setReadyV3(true)
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}
	if err != nil {
		m.statusError("Failed to complete upgrade. Retry command.")
		m.statusBullet("cause: %v", err)
		return MigrationError{Type: ErrorGeneric, Err: err}
	}
	m.status("Upgrade completed successfully")
	return nil
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

func (m *migrationHelper) v3DatastoreIsClean() (bool, error) {
	bc := m.clientv3.(backend).Backend()
	if i, ok := bc.(ic); ok {
		return i.IsClean()
	}
	return true, nil
}

// queryAndConvertResources queries the v1 resources and converts them to the equivalent
// v3 resources.
// This method returns an error if it is unable to query the current v1 settings.
// Errors from the conversion are returned within the MigrationData - this function will
// attempt to convert everything before returning with the set of converted data and
// conversion errors - this allows a full pre-migration report to be generated in a single
// shot.
func (m *migrationHelper) queryAndConvertResources() (*MigrationData, error) {
	data := &MigrationData{}

	// Query and convert global felix configuration and cluster info.
	if err := m.queryAndConvertFelixConfigV1ToV3(data); err != nil {
		return nil, err
	}

	m.statusBullet("handling BGPConfiguration (global) resource")
	// Query the global BGP configuration:  default AS number; node-to-node mesh.
	if err := m.queryAndConvertGlobalBGPConfigV1ToV3(data); err != nil {
		return nil, err
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping Node resources - these do not need migrating")
	} else {
		m.statusBullet("handling Node resources")
		// Query and convert the Nodes
		if err := m.queryAndConvertV1ToV3Nodes(data); err != nil {
			return nil, err
		}
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping BGPPeer (global) resources - these do not need migrating")
	} else {
		m.statusBullet("handling BGPPeer (global) resources")
		// Query and convert the BGPPeers
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.GlobalBGPPeerListOptions{}, converters.BGPPeer{}, noFilter,
		); err != nil {
			return nil, err
		}
	}

	m.statusBullet("handling BGPPeer (node) resources")
	if err := m.queryAndConvertV1ToV3Resources(
		data, model.NodeBGPPeerListOptions{}, converters.BGPPeer{}, noFilter,
	); err != nil {
		return nil, err
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping HostEndpoint resources - not supported")
	} else {
		m.statusBullet("handling HostEndpoint resources")
		// Query and convert the HostEndpoints
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.HostEndpointListOptions{}, converters.HostEndpoint{}, noFilter,
		); err != nil {
			return nil, err
		}
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping IPPool resources - these do not need migrating")
	} else {
		m.statusBullet("handling IPPool resources")
		// Query and convert the IPPools
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.IPPoolListOptions{}, converters.IPPool{}, noFilter,
		); err != nil {
			return nil, err
		}
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping GlobalNetworkPolicy resources - these do not need migrating")
	} else {
		m.statusBullet("handling GlobalNetworkPolicy resources")
		// Query and convert the Policies
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.PolicyListOptions{}, converters.Policy{}, filterGNP,
		); err != nil {
			return nil, err
		}
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping Profile resources - these do not need migrating")
	} else {
		m.statusBullet("handling Profile resources")
		// Query and convert the Profiles
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.ProfileListOptions{}, converters.Profile{}, filterProfile,
		); err != nil {
			return nil, err
		}
	}

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping WorkloadEndpoint resources - these do not need migrating")
	} else {
		m.statusBullet("handling WorkloadEndpoint resources")
		// Query and convert the WorkloadEndpoints
		if err := m.queryAndConvertV1ToV3Resources(
			data, model.WorkloadEndpointListOptions{}, converters.WorkloadEndpoint{}, noFilter,
		); err != nil {
			return nil, err
		}
	}

	return data, nil
}

// Query the v1 format resources and convert to the v3 format. Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func (m *migrationHelper) queryAndConvertV1ToV3Resources(
	data *MigrationData,
	listInterface model.ListInterface,
	converter converters.Converter,
	filterOut policyCtrlFilterOut,
) error {
	// Start by listing the results from the v1 client.
	kvps, err := m.clientv1.List(listInterface)
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

func (m *migrationHelper) queryAndConvertGlobalBGPConfigV1ToV3(data *MigrationData) error {
	globalBGPConfig := apiv3.NewBGPConfiguration()
	globalBGPConfig.Name = "default"

	log.Info("Converting BGP config -> BGPConfiguration(default)")
	var setValue bool
	if kvp, err := m.clientv1.Get(model.GlobalBGPConfigKey{Name: "AsNumber"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global default ASNumber configured")
	} else if kvp.Value.(string) != "" {
		asNum, err := numorstring.ASNumberFromString(kvp.Value.(string))
		if err != nil {
			log.WithError(err).WithField("ASNumber", kvp.Value).Info("Invalid global default ASNumber")
			data.ConversionErrors = append(data.ConversionErrors, ConversionError{
				ValueV1: kvp.Value,
				Cause:   fmt.Errorf("default ASNumber is not valid: %s", kvp.Value.(string)),
			})
			return err
		}
		globalBGPConfig.Spec.ASNumber = &asNum
		setValue = true
	}

	if kvp, err := m.clientv1.Get(model.GlobalBGPConfigKey{Name: "LogLevel"}); err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
			return err
		}
		log.Info("No global BGP log level configured")
	} else if kvp.Value.(string) != "" {
		globalBGPConfig.Spec.LogSeverityScreen = convertLogLevel(kvp.Value.(string))
		setValue = true
	}

	if kvp, err := m.clientv1.Get(model.GlobalBGPConfigKey{Name: "NodeMeshEnabled"}); err != nil {
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
		data.Resources = append(data.Resources, globalBGPConfig)
	}
	return nil
}

// Query the v1 format resources and convert to the v3 format. Successfully
// migrated resources are appended to res, and conversion errors to convErr.
func (m *migrationHelper) queryAndConvertV1ToV3Nodes(data *MigrationData) error {
	// Start by querying the nodes and converting them, we don't add the nodes to the list
	// of results just yet.
	err := m.queryAndConvertV1ToV3Resources(
		data, model.NodeListOptions{}, converters.Node{}, noFilter,
	)
	if err != nil {
		return err
	}

	// Query all of the per-node config and extract all of the IPIP tunnel addresses that are
	// configured.
	kvps, err := m.clientv1.List(model.HostConfigListOptions{Name: "IpInIpTunnelAddr"})
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
		addrs[converters.ConvertNodeName(k.Hostname)] = kvp.Value.(string)
	}

	// Update the node resources to include the tunnel addresses.  Loop through the converted
	// resources and modify any node that has a corresponding tunnel address (it's a pointer
	// so we can adjust the in-situ resource).
	for _, r := range data.Resources {
		if nr, ok := r.(*apiv3.Node); ok {
			addr := addrs[nr.Name]
			if addr == "" || nr.Spec.BGP == nil {
				continue
			}
			nr.Spec.BGP.IPv4IPIPTunnelAddr = addr
		}
	}

	return nil
}

// ShouldMigrate checks version information and reports if migration is needed
// and is possible.
func (m *migrationHelper) ShouldMigrate() (bool, error) {
	ci, err := m.clientv3.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		if yes, err := versionRequiresMigration(ci.Spec.CalicoVersion); err != nil {
			log.Errorf("Could not parse CalicoVersion %s in ClusterInformation: %v", ci.Spec.CalicoVersion, err)
			return true, err
		} else if yes {
			log.Debugf("ClusterInformation contained CalicoVersion %s and indicates migration is needed", ci.Spec.CalicoVersion)
			return true, nil
		}
		log.Debugf("ClusterInformation contained CalicoVersion %s and indicates migration is not needed", ci.Spec.CalicoVersion)
		return false, nil
	} else if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
		// The error indicates a problem with accessing the resource
		return false, err
	}
	// The resource does not exist from the clientv3 so we need to check the
	// clientv1 version.

	// Grab the version from the clientv1
	v, err := m.getV1ClusterVersion()
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.Debugf("CalicoVersion does exist in the v1 or v3 data, no migration needed")
			// The resource does not exist in the clientv1 (or in the clientv3)
			// so no migration is needed because it seems that this is an
			// unitialized datastore.
			return false, nil
		}

		// The error indicates a problem accessing the resource.
		return false, err
	}

	// Migrate only if it is possible to migrate from the current version
	if yes, err := versionRequiresMigration(v); err != nil {
		log.Errorf("Unable to migrate version %s: %v", v, err)
		return false, fmt.Errorf("Unable to migrate version %s: %v", v, err)
	} else if !yes {
		log.Errorf("Migration to v3 requires a base of Calico v2.6.4+, currently at %s", v)
		return false, errors.New(fmt.Sprintf("Migration to v3 requires a base of Calico v2.6.4+, currently at %s", v))
	}
	log.Debugf("GlobalConfig contained CalicoVersion %s and indicates migration is needed", v)
	return true, nil
}

// getV1ClusterVersion reads the CalicoVersion from the v1 client interface.
func (m *migrationHelper) getV1ClusterVersion() (string, error) {
	kv, err := m.clientv1.Get(model.GlobalConfigKey{Name: "CalicoVersion"})
	if err == nil {
		return kv.Value.(string), nil
	}
	return "", err
}

// versionRequiresMigration returns true if the given version requires
// upgrating the data model, false otherwise. Returns an error if it was
// not possible to parse the version, or if the version was less than the
// minimum requires for upgrade.
func versionRequiresMigration(v string) (bool, error) {
	sv, err := semver.NewVersion(strings.TrimPrefix(v, "v"))
	if err != nil {
		log.Warnf("Unable to parse Calico version %s: %v", v, err)
		return false, fmt.Errorf("Error converting version %s", v)
	}

	if sv.Major >= 3 {
		log.Debugf("major version is already >= 3: %s", v)
		// No need to migrate 3.0 or greater
		return false, nil
	}

	// Using 2.6.3 for the comparison point because '2.6.4-rc1' is LessThan
	// '2.6.4', and we want the -rc1 to be upgradeable.
	sv263 := semver.New("2.6.3")
	if sv263.LessThan(*sv) {
		// Version is greater than or equal to 2.6.4 and less than 3.0
		return true, nil
	}

	// Version is less than 2.6.4 (including pre-releases). This is an
	// error case and we cannot allow upgrade to continue.
	log.Infof("Cannot migrate from version %s", v)
	return false, fmt.Errorf("Migration to v3 requires a base of Calico v2.6.4+, currently at %s", v)
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

// Display a 79-char word wrapped status message and log.
func (m *migrationHelper) status(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if m.statusWriter != nil {
		m.statusWriter.Msg(msg)
	}
}

// Display a 79-char word wrapped sub status (a bulleted message) and log.
func (m *migrationHelper) statusBullet(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Info(strings.TrimSpace(msg))
	if m.statusWriter != nil {
		m.statusWriter.Bullet(msg)
	}
}

// Display a 79-char word wrapped error message and log.
func (m *migrationHelper) statusError(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Error(strings.TrimSpace(msg))
	if m.statusWriter != nil {
		m.statusWriter.Error(msg)
	}
}

// setReadyV1 sets the ready flag in the v1 datastore.
func (m *migrationHelper) setReadyV1(ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v1")
	_, err := m.clientv1.Apply(&model.KVPair{
		Key:   model.ReadyFlagKey{},
		Value: ready,
	})
	if err != nil {
		if ready {
			m.statusBullet("failed to resume Calico networking in the v1 configuration")
		} else {
			m.statusBullet("failed to pause Calico networking in the v1 configuration")
		}
	}
	if ready {
		m.statusBullet("successfully resumed Calico networking in the v1 configuration")
	} else {
		m.statusBullet("successfully paused Calico networking in the v1 configuration")
	}
	return nil
}

// setReadyV1 sets the ready flag in the v3 datastore.
func (m *migrationHelper) setReadyV3(ready bool) error {
	log.WithField("Ready", ready).Info("Updating Ready flag in v3")
	c, err := m.clientv3.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
	if err == nil {
		// ClusterInformation already exists - update the settings.
		log.WithField("Ready", ready).Info("Updating Ready flag in v3 ClusterInformation")
		c.Spec.DatastoreReady = &ready
		_, err = m.clientv3.ClusterInformation().Update(context.Background(), c, options.SetOptions{})
		if err != nil {
			log.WithError(err).Info("Hit error setting ready flag in v3 ClusterInformation")
			if ready {
				m.statusBullet("failed to resume Calico networking in the v3 configuration: %v", err)
			} else {
				m.statusBullet("failed to pause Calico networking in the v3 configuration: %v", err)
			}
			return err
		}
		if ready {
			m.statusBullet("successfully resumed Calico networking in the v3 configuration (updated ClusterInformation)")
		} else {
			m.statusBullet("successfully paused Calico networking in the v3 configuration (updated ClusterInformation)")
		}
		return nil
	}

	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); !ok {
		// ClusterInformation could not be queried.
		if ready {
			m.statusBullet("failed to resume Calico networking in the v3 configuration (unable to query ClusterInformation)")
		} else {
			m.statusBullet("failed to pause Calico networking in the v3 configuration (unable to query ClusterInformation)")
		}
		return err
	}

	// ClusterInformation does not exist - create a new one.
	c = apiv3.NewClusterInformation()
	c.Name = "default"
	c.Spec.DatastoreReady = &ready
	_, err = m.clientv3.ClusterInformation().Create(context.Background(), c, options.SetOptions{})
	if err != nil {
		if ready {
			m.statusBullet("failed to resume Calico networking in the v3 configuration (unable to create ClusterInformation)")
		} else {
			m.statusBullet("failed to pause Calico networking in the v3 configuration (unable to create ClusterInformation)")
		}
		return err
	}
	if ready {
		m.statusBullet("successfully resumed Calico networking in the v1 configuration (created ClusterInformation)")
	} else {
		m.statusBullet("successfully paused Calico networking in the v1 configuration (created ClusterInformation)")
	}
	return nil
}

// resourceToKey creates a model.Key from a v3 resource.
func resourceToKey(r converters.Resource) model.Key {
	return model.ResourceKey{
		Kind:      r.GetObjectKind().GroupVersionKind().Kind,
		Name:      r.GetObjectMeta().GetName(),
		Namespace: r.GetObjectMeta().GetNamespace(),
	}
}

// storeV3Resources stores the converted resources in the v3 datastore.
func (m *migrationHelper) storeV3Resources(data *MigrationData) error {
	m.statusBullet("Storing resources in v3 format")
	for n, r := range data.Resources {
		// Convert the resource to a KVPair and access the backend datastore directly.
		// This is slightly more efficient, and cuts out some of the unneccessary additional
		// processing. Since we applying directly to the backend we need to set the UUID
		// and creation timestamp which is normally handled by clientv3.
		r.GetObjectMeta().SetCreationTimestamp(metav1.Now())
		r.GetObjectMeta().SetUID(uuid.NewUUID())
		if err := m.applyToBackend(&model.KVPair{
			Key:   resourceToKey(r),
			Value: r,
		}); err != nil {
			return err
		}

		if (n+1)%numAppliesPerUpdate == 0 {
			m.statusBullet("applied %d resources", (n + 1))
		}
	}
	m.statusBullet("success: resources stored in v3 datastore")
	return nil
}

// migrateIPAMData queries, converts and migrates all of the IPAM data from v1
// to v3 formats.
func (m *migrationHelper) migrateIPAMData() error {
	var kvpsv3 []*model.KVPair

	// Query all of the IPAM data:
	// -  Blocks
	// -  BlockAffinity
	// -  IPAMHandle
	// AllocationBlocks need to have their host affinity updated to use the
	// normalized node name.
	m.statusBullet("listing and converting IPAM allocation blocks")
	kvps, err := m.clientv1.List(model.BlockListOptions{})
	if err != nil {
		m.statusError("Unable to list IPAM allocation blocks")
		m.statusBullet("cause: %v", err)
		return fmt.Errorf("unable to list IPAM allocation blocks: %v", err)
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
			aff := "host:" + converters.ConvertNodeName(node)
			ab.Affinity = &aff
		}
		kvpsv3 = append(kvpsv3, kvp)
	}

	// BlockAffinities need to have their host updated to use the
	// normalized node name.
	m.statusBullet("listing and converting IPAM affinity blocks")
	kvps, err = m.clientv1.List(model.BlockAffinityListOptions{})
	if err != nil {
		m.statusError("Unable to list IPAM affinity blocks")
		m.statusBullet("cause: %v", err)
		return fmt.Errorf("unable to list IPAM affinity blocks: %v", err)
	}
	for _, kvp := range kvps {
		k := kvp.Key.(model.BlockAffinityKey)
		k.Host = converters.ConvertNodeName(k.Host)
		kvp.Key = k
		kvpsv3 = append(kvpsv3, kvp)
	}

	// IPAMHandle does not require any conversion.
	m.statusBullet("listing IPAM handles")
	kvps, err = m.clientv1.List(model.IPAMHandleListOptions{})
	if err != nil {
		m.statusError("Unable to list IPAM handles")
		m.statusBullet("cause: %v", err)
		return fmt.Errorf("unable to list IPAM handles: %v", err)
	}
	kvpsv3 = append(kvpsv3, kvps...)

	// Create/Apply the converted entries into the v3 datastore.
	m.statusBullet("storing IPAM data in v3 format")
	for _, kvp := range kvpsv3 {
		if err := m.applyToBackend(kvp); err != nil {
			m.statusError("Error writing IPAM data to v3 datastore")
			return fmt.Errorf("error storing converted IPAM data: %v", err)
		}
	}

	// We migrated the data successfully.
	m.statusBullet("IPAM data migrated successfully")
	return nil
}

// backend is an interface used to access the backend client from the main clientv3.
type backend interface {
	Backend() bapi.Client
}

// applyToBackend applies the supplied KVPair directly to the backend datastore.
func (m *migrationHelper) applyToBackend(kvp *model.KVPair) error {
	// Extract the backend API from the v3 client.
	bc := m.clientv3.(backend).Backend()

	// First try creating the resource. If the resource already exists, try an update.
	logCxt := log.WithField("Key", kvp.Key)
	logCxt.Debug("Attempting to create resource")
	kvp.Revision = ""
	_, err := bc.Create(context.Background(), kvp)
	if err == nil {
		logCxt.Debug("Resource created")
		return nil
	}
	if _, ok := err.(cerrors.ErrorResourceAlreadyExists); !ok {
		logCxt.WithError(err).Info("Failed to create resource")
		return err
	}

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

		// We hit a resource update conflict - pause for a short duration before
		// retrying.
		time.Sleep(time.Duration(float64(retryInterval) * (1 + (0.1 * rand.Float64()))))
	}

	logCxt.WithError(err).Info("Failed to update resource")
	return err
}
