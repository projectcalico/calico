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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/upgrade/converters"
)

// Query the v1 format of GlobalConfigList and convert to the v3 format of
// FelixConfiguration and ClusterInformation.
func (m *migrationHelper) queryAndConvertFelixConfigV1ToV3(
	data *MigrationData,
) error {
	// Query all of the global config into a slice of KVPairs.
	m.statusBullet("handling FelixConfiguration (global) resource")
	kvps, err := m.clientv1.List(model.GlobalConfigListOptions{})
	if err != nil {
		return fmt.Errorf("error querying FelixConfiguration: %v", err)
	}

	// Parse the separate KVPairs into a global FelixConfiguration resource and a
	// global ClusterInformation resource. Note that if this is KDD we set the Ready
	// flag to true, otherwise to false.
	globalConfig := apiv3.NewFelixConfiguration()
	globalConfig.Name = "default"
	if err := m.parseFelixConfigV1IntoResourceV3(kvps, globalConfig, data); err != nil {
		return fmt.Errorf("error converting FelixConfiguration: %v", err)
	}

	m.statusBullet("handling ClusterInformation (global) resource")
	clusterInfo := apiv3.NewClusterInformation()
	clusterInfo.Name = "default"
	if err = m.parseFelixConfigV1IntoResourceV3(kvps, clusterInfo, data); err != nil {
		return fmt.Errorf("error converting ClusterInformation: %v", err)
	}
	// Update the ready flag in the resource based on the datastore type.  For KDD the ready
	// flag should be true, for etcd it should be false.
	ready := m.clientv1.IsKDD()
	clusterInfo.Spec.DatastoreReady = &ready

	if m.clientv1.IsKDD() {
		m.statusBullet("skipping FelixConfiguration (per-node) resources - not supported")
	} else {
		// Query all of the per-host felix config into a slice of KVPairs.
		m.statusBullet("handling FelixConfiguration (per-node) resources")
		kvps, err = m.clientv1.List(model.HostConfigListOptions{})
		if err != nil {
			return fmt.Errorf("error querying FelixConfiguration: %v", err)
		}

		// Sort the configuration into slices of KVPairs for each node, converting the
		// nodename as we go.
		nodeKvps := make(map[string][]*model.KVPair, 0)
		for _, kvp := range kvps {
			// Extract the key, update it and store the updated key. Store in the node-specific
			// bucket.
			hk := kvp.Key.(model.HostConfigKey)
			hk.Hostname = converters.ConvertNodeName(hk.Hostname)
			kvp.Key = hk

			nodeKvps[hk.Hostname] = append(nodeKvps[hk.Hostname], kvp)
		}

		// For each node, get the felix config kvps and convert to v3 per-node
		// FelixConfiguration resource.
		for node, kvps := range nodeKvps {
			// Convert to v3 resource.
			nodeConfig := apiv3.NewFelixConfiguration()
			nodeConfig.Name = fmt.Sprintf("node.%s", node)
			if err := m.parseFelixConfigV1IntoResourceV3(kvps, nodeConfig, data); err != nil {
				return fmt.Errorf("error converting FelixConfiguration: %v", err)
			}
		}
	}

	return nil
}

// This function converts a slice of v1 KVPairs into the appropriate v3 values and
// merges the results into a single v3 resource Spec for felix configuration (global
// or per host) or a clusterInfo.
// Conversion errors are added to the MigrationData struct.
func (m *migrationHelper) parseFelixConfigV1IntoResourceV3(
	kvps []*model.KVPair,
	res converters.Resource,
	data *MigrationData,
) error {
	logCxtRes := log.WithFields(log.Fields{
		"kind": res.GetObjectKind().GroupVersionKind().Kind,
		"name": res.GetObjectMeta().GetName(),
	})

	// Convert the KVP slice into a name value map.
	keysv1 := map[string]model.Key{}
	configv1 := map[string]string{}
	for _, kvp := range kvps {
		if kvp.Value == nil {
			continue
		}
		switch key := kvp.Key.(type) {
		case model.GlobalConfigKey:
			configv1[key.Name] = kvp.Value.(string)
			keysv1[key.Name] = key
		case model.HostConfigKey:
			configv1[key.Name] = kvp.Value.(string)
			keysv1[key.Name] = key
		}
	}

	// Extract the Spec from the resource FelixConfiguration or ClusterInfo.
	specValue := reflect.ValueOf(res).Elem().FieldByName("Spec")
	if !specValue.IsValid() {
		return fmt.Errorf("unable to process config resource type: %v", res)
	}

	// Loop through the Spec setting each field from the supplied KVPair data.
	setField := false
	specType := specValue.Type()
	for i := 0; i < specType.NumField(); i++ {
		field := specType.Field(i)
		fieldValue := specValue.Field(i)

		// Get the v1 config value associated with the field.
		configName := m.getConfigName(field)
		logCxt := logCxtRes.WithFields(log.Fields{
			"field":      field.Name,
			"configName": configName,
		})
		configStrValue, ok := configv1[configName]
		if !ok {
			logCxt.Debug("config value is not configured in v1")
			continue
		}

		isPtr := field.Type.Kind() == reflect.Ptr
		fieldName := field.Name

		switch {
		case strings.HasPrefix(fieldName, "Failsafe"):
			// Special-case the Failsafe ports - these require parsing and settings as a struct.
			if configStrValue == "none" {
				// Has no failsafe ports
				vProtoPort := &[]apiv3.ProtoPort{}
				fieldValue.Set(reflect.ValueOf(vProtoPort))
				setField = true
				continue
			}

			vProtoPort, err := m.parseProtoPort(configStrValue)
			if err != nil {
				logCxt.WithError(err).Info("Failed to parse field")
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{
					Cause:   err,
					KeyV1:   keysv1[configName],
					ValueV1: configStrValue,
					KeyV3:   resourceToKey(res),
				})
				continue
			}
			fieldValue.Set(reflect.ValueOf(vProtoPort)) // pointer to proto port slice.
			setField = true
			continue
		case strings.HasPrefix(fieldName, "LogSeverity"):
			// The log level fields need to have their value converted to the appropriate v3 value,
			// but other than that are treated as normal string fields.
			configStrValue = convertLogLevel(configStrValue)
		}

		_, ok = fieldValue.Interface().(*metav1.Duration)
		if ok {
			if duration, err := strconv.ParseFloat(configStrValue, 64); err != nil {
				logCxt.WithError(err).Info("Failed to parse float for Duration field")
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{
					Cause:   fmt.Errorf("failed to parse float for Duration field: %v", err),
					KeyV1:   keysv1[configName],
					ValueV1: configStrValue,
					KeyV3:   resourceToKey(res),
				})
			} else {
				switch field.Tag.Get("configv1timescale") {
				case "milliseconds":
					fieldValue.Set(reflect.ValueOf(&metav1.Duration{Duration: time.Duration(duration * float64(time.Millisecond))}))
				default:
					fieldValue.Set(reflect.ValueOf(&metav1.Duration{Duration: time.Duration(duration * float64(time.Second))}))
				}
				setField = true
				continue
			}
		}

		// Set the field value based on the field type.
		var kind reflect.Kind
		if isPtr {
			kind = field.Type.Elem().Kind()
		} else {
			kind = fieldValue.Kind()
		}

		switch kind {
		case reflect.Uint32:
			if value, err := strconv.ParseUint(configStrValue, 10, 32); err != nil {
				logCxt.WithError(err).Info("Failed to parse uint32 field")
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{
					Cause:   fmt.Errorf("failed to parse uint32 field: %v", err),
					KeyV1:   keysv1[configName],
					ValueV1: configStrValue,
					KeyV3:   resourceToKey(res),
				})
				continue
			} else if isPtr {
				vu := uint32(value)
				fieldValue.Set(reflect.ValueOf(&vu))
			} else {
				fieldValue.SetUint(value)
			}
		case reflect.Int:
			if value, err := strconv.ParseInt(configStrValue, 10, 64); err != nil {
				logCxt.WithError(err).Info("Failed to parse int field")
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{
					Cause:   fmt.Errorf("failed to parse int field: %v", err),
					KeyV1:   keysv1[configName],
					ValueV1: configStrValue,
					KeyV3:   resourceToKey(res),
				})
				continue
			} else if isPtr {
				vi := int(value)
				fieldValue.Set(reflect.ValueOf(&vi))
			} else {
				fieldValue.SetInt(value)
			}
		case reflect.Bool:
			if value, err := strconv.ParseBool(configStrValue); err != nil {
				logCxt.WithError(err).Info("Failed to parse bool field")
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{
					Cause:   fmt.Errorf("failed to parse bool field: %v", err),
					KeyV1:   keysv1[configName],
					ValueV1: configStrValue,
					KeyV3:   resourceToKey(res),
				})
				continue
			} else if isPtr {
				fieldValue.Set(reflect.ValueOf(&value))
			} else {
				fieldValue.SetBool(value)
			}
		case reflect.String:
			if isPtr {
				fieldValue.Set(reflect.ValueOf(&configStrValue))
			} else {
				fieldValue.SetString(configStrValue)
			}
		default:
			logCxt.Info("Unhandle field type")
			data.ConversionErrors = append(data.ConversionErrors, ConversionError{
				Cause: fmt.Errorf("unhandled field type, please raise an issue on GitHub " +
					"(https://github.com/projectcalico/calico) that includes this error message"),
				KeyV1:   keysv1[configName],
				ValueV1: configStrValue,
				KeyV3:   resourceToKey(res),
			})
			continue
		}

		// We must have set a field in the spec.
		setField = true
	}

	if setField {
		data.Resources = append(data.Resources, res)
	}
	return nil
}

func (m *migrationHelper) parseProtoPortFailed(msg string) error {
	return fmt.Errorf("failed to parse ProtoPort-%s", msg)
}

func (m *migrationHelper) parseProtoPort(raw string) (*[]apiv3.ProtoPort, error) {
	var result []apiv3.ProtoPort
	for _, portStr := range strings.Split(raw, ",") {
		portStr = strings.Trim(portStr, " ")
		if portStr == "" {
			continue
		}

		protocolStr := "tcp"
		netStr := ""

		// Check if IPv6 network is set
		if strings.Contains(portStr, "[") && strings.Contains(portStr, "]") {
			// Grab the IPv6 network
			startIndex := strings.Index(portStr, "[")
			endIndex := strings.Index(portStr, "]:")
			netStr = portStr[startIndex+1 : endIndex]

			// Remove the IPv6 network value from portStr
			var withoutIPv6 strings.Builder
			withoutIPv6.WriteString(portStr[:startIndex])
			withoutIPv6.WriteString(portStr[endIndex+2:])
			portStr = withoutIPv6.String()
		}

		parts := strings.Split(portStr, ":")
		if len(parts) > 3 {
			return nil, m.parseProtoPortFailed("ports should be <protocol>:<net>:<number> or <protocol>:<number> or <number>")
		}

		if len(parts) > 2 {
			netStr = parts[1]
			protocolStr = strings.ToUpper(parts[0])
			portStr = parts[2]
		}

		if len(parts) == 2 {
			protocolStr = strings.ToUpper(parts[0])
			portStr = parts[1]
		}

		if protocolStr != "TCP" && protocolStr != "UDP" {
			return nil, m.parseProtoPortFailed("unknown protocol: " + protocolStr)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, m.parseProtoPortFailed("ports should be integers")
		}
		if port < 0 || port > 65535 {
			err = m.parseProtoPortFailed("ports must be in range 0-65535")
			return nil, err
		}

		protoPort := apiv3.ProtoPort{
			Protocol: protocolStr,
			Port:     uint16(port),
		}

		if netStr != "" {
			_, netParsed, err := net.ParseCIDROrIP(netStr)
			if err != nil {
				err = m.parseProtoPortFailed("invalid CIDR or IP " + netStr)
				return nil, err
			}
			protoPort.Net = netParsed.String()
		}

		result = append(result, protoPort)
	}

	return &result, nil
}

// Return the config name from the field. The field name is either specified in the
// configname tag, otherwise it just uses the struct field name.
func (m *migrationHelper) getConfigName(field reflect.StructField) string {
	name := field.Tag.Get("confignamev1")
	if name == "" {
		name = field.Name
	}
	return name
}
