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

package updateprocessors

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const (
	AllowAnnotations    = true
	DisallowAnnotations = false
)

// NewConfigUpdateProcessor creates a SyncerUpdateProcessor that can be used to map
// Configuration-type resources to the v1 model.  This converter basically
// expands each field as a separate key and uses a stringified of the field as the
// configuration value.  If the field is not specified in the configuration resource
// we expand that that a delete for the associated key.
//
// If the field specifies a "confignamev1" tag, then the value in that tag is used
// as the config name, otherwise the struct field name is used.
//
// A set of ValueToStringFn can be specified for each of the (converted) field names
// to handle marshaling the field value into the string value required in the v1
// model.
//
// It is assumed that the name of the resource follows the format:
// - `default` for global
// - `node.<nodename>` for per-node
//
// If allowAnnotations is set to true, then this helper will also check the annotations
// for additional config key/values.  An annotation prefixed with "config.projectcalico.org/"
// will be used (prefix removed) as the config key, and the value of the annotation used as
// the value.  These values are not validated, and take precedence over keys of the same
// name in the Spec - thus it's possible to use an annotation to work around any validation
// provided on the Spec.
func NewConfigUpdateProcessor(
	specType reflect.Type,
	allowAnnotations bool,
	nodeConfigKeyFn NodeConfigKeyFn,
	globalConfigKeyFn GlobalConfigKeyFn,
	valueConverters map[string]ConfigFieldValueToV1ModelValue,
) watchersyncer.SyncerUpdateProcessor {
	names := make(map[string]struct{}, specType.NumField())
	for i := 0; i < specType.NumField(); i++ {
		names[getConfigName(specType.Field(i))] = struct{}{}
	}
	return &configUpdateProcessor{
		specType:          specType,
		allowAnnotations:  allowAnnotations,
		nodeConfigKeyFn:   nodeConfigKeyFn,
		globalConfigKeyFn: globalConfigKeyFn,
		names:             names,
		additionalNames:   map[string]struct{}{},
		valueConverters:   valueConverters,
	}
}

// Convert the node and config name to the corresponding per-node config key
type NodeConfigKeyFn func(node, name string) model.Key

// Convert the config name to the corresponding global config key
type GlobalConfigKeyFn func(name string) model.Key

// Convert an arbitrary value to the value used in the v1 model.
type ConfigFieldValueToV1ModelValue func(value interface{}) interface{}

var (
	globalConfigName        = "default"
	perNodeConfigNamePrefix = "node."
	annotationConfigPrefix  = "config.projectcalico.org/"
)

// configUpdateProcessor implements the SyncerUpdateProcessor interface for converting
// between v3 configuration resources (FelixConfiguration and ClusterInformation) and
// individual global or per-node values.
//
// This helper class uses the name of the resource to determine whether the
// converted resource is global or per-node, and then creates a separate update for
// each field, using either the name of the field or the value in the confignamev1 tag
// as the name of the config key and the value of the field converted to the config value.
// The struct field values are converted as follows:
//   - if the field is nil, or an empty string - the converted value is nil indicating a
//     deletion of the config key.
//   - if a converter has been provided for the field then the value is converted using
//     that converter.
//   - if it is a string field, the value is used as is.
//   - booleans and ints are stringified in the standard way
//
// This converter caches a list of additional config names that it has seen defined in
// annotations.  This is used as a simplistic mechanism for sending deletes for config
// removed from an annotation.
type configUpdateProcessor struct {
	specType          reflect.Type
	allowAnnotations  bool
	nodeConfigKeyFn   NodeConfigKeyFn
	globalConfigKeyFn GlobalConfigKeyFn
	names             map[string]struct{}
	additionalNames   map[string]struct{}
	valueConverters   map[string]ConfigFieldValueToV1ModelValue
}

func (c *configUpdateProcessor) Process(kvp *model.KVPair) ([]*model.KVPair, error) {
	if kvp.Value == nil {
		return c.processDeleted(kvp)
	} else {
		return c.processAddOrModified(kvp)
	}
}

// processDeleted is called when the syncer is processing a delete event.
func (c *configUpdateProcessor) processDeleted(kvp *model.KVPair) ([]*model.KVPair, error) {
	node, err := c.extractNode(kvp.Key)
	if err != nil {
		return nil, err
	}

	kvps := make([]*model.KVPair, len(c.names)+len(c.additionalNames))
	i := 0
	for name := range c.names {
		kvps[i] = &model.KVPair{
			Key: c.createV1Key(node, name),
		}
		i++
	}
	for name := range c.additionalNames {
		kvps[i] = &model.KVPair{
			Key: c.createV1Key(node, name),
		}
		i++
	}

	return kvps, nil
}

// processAddOrModified is called when the syncer is processing either a New or Updated event.
func (c *configUpdateProcessor) processAddOrModified(kvp *model.KVPair) ([]*model.KVPair, error) {
	node, err := c.extractNode(kvp.Key)
	if err != nil {
		log.WithField("Key", kvp.Key).Warning("Failed to extract node/global name from key")
		return nil, err
	}

	// Extract the config override annotations from the Metadata.  This in turn will validate that
	// it is a resource in the value.
	overrides, err := c.extractAnnotations(kvp)
	if err != nil {
		return nil, err
	}

	// Extract the Spec from the resource.
	specValue := reflect.ValueOf(kvp.Value).Elem().FieldByName("Spec")
	if !specValue.IsValid() || specValue.Type() != c.specType {
		log.WithFields(log.Fields{
			"SpecValue":    specValue,
			"ExpectedType": c.specType,
		}).Info("Spec is missing or incorrect type")
		return nil, errors.New("Spec is missing or incorrect type")
	}

	// Create a KVP for each field in the Spec struct.
	var kvps []*model.KVPair
	numFields := len(c.names)
	for i := 0; i < numFields; i++ {
		fieldInfo := c.specType.Field(i)
		name := getConfigName(fieldInfo)

		key := c.createV1Key(node, name)
		if key == nil {
			log.WithField("name", name).Debug("No associated v1 key, skipping field")
			continue
		}
		// If we have an override, handle explicitly and then skip to the next field.
		if v, ok := overrides[name]; ok {
			kvps = append(kvps, &model.KVPair{
				Key:      key,
				Value:    v,
				Revision: kvp.Revision,
			})

			// Delete from the overrides list to indicate it's handled.
			delete(overrides, name)
			continue
		}

		// Extract the field value and dereference pointers, storing a nil value if the pointer is nil
		// or if it's a zero length string.
		var value interface{}
		field := specValue.Field(i)
		if field.Kind() == reflect.Ptr {
			if !field.IsNil() {
				value = field.Elem().Interface()
			}
		} else {
			value = field.Interface()
			if s, ok := value.(string); ok && len(s) == 0 {
				value = nil
			}
		}

		if value != nil {
			if s, ok := c.valueConverters[name]; ok {
				// Field has a special-case conversion function, invoke it.
				value = s(value)
			} else {
				// Stringify the value according to its type.  An empty string is returned as
				// nil (i.e. delete entry).
				switch vt := value.(type) {
				case string:
					value = vt
				case v1.Duration:
					switch fieldInfo.Tag.Get("configv1timescale") {
					case "milliseconds":
						ms := vt.Duration / time.Millisecond
						nMs := vt.Duration % time.Millisecond
						value = fmt.Sprintf("%v", float64(ms)+float64(nMs)/1e6)
					default:
						value = fmt.Sprintf("%v", vt.Seconds())
					}
				case []string:
					// Make a list of strings comma delimited
					value = strings.Join(vt, ",")
				default:
					value = fmt.Sprintf("%v", vt)
				}
			}
		}

		// Add this value to the set to return.
		kvps = append(kvps, &model.KVPair{
			Key:      key,
			Value:    value,
			Revision: kvp.Revision,
		})
	}

	// Now handle the additional fields that may have been added through annotations
	// on previous requests.  This ensures we send deletes for them in case our previous
	// settings had it set.  The WatcherSyncer handles gracefully multiple deletes for
	// the same key, so it doesn't matter if it wasn't previously set.
	var value interface{}
	for name := range c.additionalNames {
		// If we have an override for this additional config option then use that value,
		// otherwise leave the value as nil to ensure we delete the option if it was
		// previously set.  Remove from the overrides map once handled.
		if v, ok := overrides[name]; ok {
			value = v
			delete(overrides, name)
		} else {
			value = nil
		}
		kvps = append(kvps, &model.KVPair{
			Key:      c.createV1Key(node, name),
			Value:    value,
			Revision: kvp.Revision,
		})
	}

	// Any remaining overrides are ones we haven't seen before.  Add them to the config and
	// include them in the additionalNames.
	for name, value := range overrides {
		kvps = append(kvps, &model.KVPair{
			Key:      c.createV1Key(node, name),
			Value:    value,
			Revision: kvp.Revision,
		})
		c.additionalNames[name] = struct{}{}
	}

	return kvps, nil
}

// Sync has restarted, so we can clear our cache of additional fields.
func (c *configUpdateProcessor) OnSyncerStarting() {
	c.additionalNames = map[string]struct{}{}
}

// extractAnnotations extracts the config override annotations from the
// configuration resource.
func (c *configUpdateProcessor) extractAnnotations(kvp *model.KVPair) (map[string]string, error) {
	ma, ok := kvp.Value.(v1.ObjectMetaAccessor)
	if !ok {
		return nil, errors.New("Unexpected value type in conversion")
	}
	overrides := map[string]string{}

	// If annotations are not allowed, don't bother extracting them - just return an empty
	// map.
	if !c.allowAnnotations {
		log.Debug("Annotations are disallowed - skipping extraction")
		return overrides, nil
	}

	annotations := ma.GetObjectMeta().GetAnnotations()
	for k, v := range annotations {
		if strings.HasPrefix(k, annotationConfigPrefix) {
			overrides[k[len(annotationConfigPrefix):]] = v
		}
	}
	return overrides, nil
}

// extractNode returns the name of the Node for which this configuration is for.  A empty string
// indicates that this is global configuration.
//
// Currently the name of a configuration resource has a strict format.  It is either "default"
// for the global default values, or "node.<nodename>" for the node specific vales.  Returns an
// error if the name is in neither format.
func (c *configUpdateProcessor) extractNode(key model.Key) (string, error) {
	k, ok := key.(model.ResourceKey)
	if !ok {
		return "", errors.New("Unexpected key type in conversion")
	}
	switch {
	case k.Name == globalConfigName:
		return "", nil
	case strings.HasPrefix(k.Name, perNodeConfigNamePrefix):
		return k.Name[len(perNodeConfigNamePrefix):], nil
	default:
		return "", cerrors.ErrorParsingDatastoreEntry{RawKey: k.Name}
	}
}

// Create the appropriate v1 config key depending on whether this global or node specific
// configuration.
func (c *configUpdateProcessor) createV1Key(node, name string) model.Key {
	if node == "" {
		return c.globalConfigKeyFn(name)
	} else {
		return c.nodeConfigKeyFn(node, name)
	}
}

// Return the config name from the field.  The field name is either specified in the
// configname tag, otherwise it just uses the struct field name.
func getConfigName(field reflect.StructField) string {
	name := field.Tag.Get("confignamev1")
	if name == "" {
		name = field.Name
	}
	return name
}
