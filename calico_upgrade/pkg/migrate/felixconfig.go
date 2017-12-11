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
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_upgrade/pkg/clients"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/upgrade/etcd/conversionv1v3"
)

type felixConfig struct{}

// Query the v1 format of GlobalConfigList and convert to the v3 format of
// FelixConfiguration and ClusterInformation.
func (fc *felixConfig) queryAndConvertFelixConfigV1ToV3(
	clientv1 clients.V1ClientInterface,
	data *ConvertedData,
) error {
	// Query all of the global config into a slice of KVPairs.
	kvps, err := clientv1.List(model.GlobalConfigListOptions{})
	if err != nil {
		return err
	}

	// Parse the separate KVPairs into a global FelixConfiguration resource and a
	// global ClusterInformation resource. Note that if this is KDD we set the Ready
	// flag to true, otherwise to false.
	globalConfig := apiv3.NewFelixConfiguration()
	globalConfig.Name = "default"
	if err := fc.parseFelixConfigV1IntoResourceV3(kvps, globalConfig, data); err != nil {
		return err
	}

	// At the point we perform the real migration the Ready flag will have been set
	// to the required value (depending on the datastore type) - this migration will
	// transfer the same value across.
	clusterInfo := apiv3.NewClusterInformation()
	clusterInfo.Name = "default"
	if err = fc.parseFelixConfigV1IntoResourceV3(kvps, clusterInfo, data); err != nil {
		return err
	}

	// Query all of the per-host felix config into a slice of KVPairs.
	kvps, err = clientv1.List(model.HostConfigListOptions{})
	if err != nil {
		return err
	}

	// Sort the configuration into slices of KVPairs for each node, converting the
	// nodename as we go.
	nodeKvps := make(map[string][]*model.KVPair, 0)
	for _, kvp := range kvps {
		// Extract the key, update it and store the updated key. Store in the node-specific
		// bucket.
		hk := kvp.Key.(model.HostConfigKey)
		hk.Hostname = conversionv1v3.ConvertNodeName(hk.Hostname)
		kvp.Key = hk

		nodeKvps[hk.Hostname] = append(nodeKvps[hk.Hostname], kvp)
	}

	// For each node, get the felix config kvps and convert to v3 per-node
	// FelixConfiguration resource.
	for node, kvps := range nodeKvps {
		// Convert to v3 resource.
		nodeConfig := apiv3.NewFelixConfiguration()
		nodeConfig.Name = fmt.Sprintf("node.%s", node)
		if err := fc.parseFelixConfigV1IntoResourceV3(kvps, nodeConfig, data); err != nil {
			return err
		}
	}

	return nil
}

// This function converts a slice of v1 KVPairs into the appropriate v3 values and
// merges the results into a single v3 resource Spec for felix configuration (global
// or per host) or a clusterInfo.
// Conversion errors are added to the ConvertedData struct.
func (fc *felixConfig) parseFelixConfigV1IntoResourceV3(
	kvps []*model.KVPair,
	res conversionv1v3.Resource,
	data *ConvertedData,
) error {
	logCxtRes := log.WithFields(log.Fields{
		"kind": res.GetObjectKind().GroupVersionKind().Kind,
		"name": res.GetObjectMeta().GetName(),
	})

	// Convert the KVP slice into a name value map.
	config := map[string]string{}
	for _, kvp := range kvps {
		if kvp.Value == nil {
			continue
		}
		switch key := kvp.Key.(type) {
		case model.GlobalConfigKey:
			config[key.Name] = kvp.Value.(string)
		case model.HostConfigKey:
			config[key.Name] = kvp.Value.(string)
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
		configName := fc.getConfigName(field)
		logCxt := logCxtRes.WithFields(log.Fields{
			"field":  field.Name,
			"config": configName,
		})
		configStrValue, ok := config[configName]
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
				continue
			}

			vProtoPort, err := fc.parseProtoPort(configStrValue)
			if err != nil {
				data.ConversionErrors = append(data.ConversionErrors, ConversionError{})
			}
			fieldValue.Set(reflect.ValueOf(vProtoPort)) // pointer to proto port slice.
			continue
		case strings.HasPrefix(fieldName, "LogSeverity"):
			// The log level fields need to have their value converted to the appropriate v3 value,
			// but other than that are treated as normal string fields.
			configStrValue = convertLogLevel(configStrValue)
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
				continue
			} else if isPtr {
				vu := uint32(value)
				fieldValue.Set(reflect.ValueOf(&vu))
			} else {
				fieldValue.SetUint(value)
			}
		case reflect.Int:
			if value, err := strconv.ParseInt(configStrValue, 10, 64); err != nil {
				continue
			} else if isPtr {
				vi := int(value)
				fieldValue.Set(reflect.ValueOf(&vi))
			} else {
				fieldValue.SetInt(value)
			}
		case reflect.Bool:
			if value, err := strconv.ParseBool(configStrValue); err != nil {
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

func (fc *felixConfig) parseProtoPortFailed(msg string) error {
	return errors.New(fmt.Sprintf("Failed to parse ProtoPort-%s", msg))
}

func (fc *felixConfig) parseProtoPort(raw string) (*[]apiv3.ProtoPort, error) {
	var result []apiv3.ProtoPort
	for _, portStr := range strings.Split(raw, ",") {
		portStr = strings.Trim(portStr, " ")
		if portStr == "" {
			continue
		}

		parts := strings.Split(portStr, ":")
		if len(parts) > 2 {
			return nil, fc.parseProtoPortFailed("ports should be <protocol>:<number> or <number>")
		}
		protocolStr := "TCP"
		if len(parts) > 1 {
			protocolStr = strings.ToUpper(parts[0])
			portStr = parts[1]
		}
		if protocolStr != "TCP" && protocolStr != "UDP" {
			return nil, fc.parseProtoPortFailed("unknown protocol: " + protocolStr)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fc.parseProtoPortFailed("ports should be integers")
		}
		if port < 0 || port > 65535 {
			err = fc.parseProtoPortFailed("ports must be in range 0-65535")
			return nil, err
		}
		result = append(result, apiv3.ProtoPort{
			Protocol: protocolStr,
			Port:     uint16(port),
		})
	}

	return &result, nil
}

// Return the config name from the field. The field name is either specified in the
// configname tag, otherwise it just uses the struct field name.
func (fc *felixConfig) getConfigName(field reflect.StructField) string {
	name := field.Tag.Get("confignamev1")
	if name == "" {
		name = field.Name
	}
	return name
}
