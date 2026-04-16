// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.

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
	"fmt"
	"reflect"
	"strings"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// FelixValueConverters maps FelixConfigurationSpec field names to their
// special-case value converter functions. These are needed both by the
// configUpdateProcessor (for v1 config decomposition) and by
// ExtractConfigFromFelixSpec (for selector-scoped config extraction).
var FelixValueConverters = map[string]ConfigFieldValueToV1ModelValue{
	"FailsafeInboundHostPorts":  protoPortSliceToString,
	"FailsafeOutboundHostPorts": protoPortSliceToString,
	"RouteTableRange":           routeTableRangeToString,
	"RouteTableRanges":          routeTableRangeListToString,
	"HealthTimeoutOverrides":    healthTimeoutOverridesToString,
	"BPFConntrackTimeouts":      bpfConntrackTimeoutsToString,
}

// Create a new SyncerUpdateProcessor to sync FelixConfiguration data in v1 format for
// consumption by Felix.
func NewFelixConfigUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConfigUpdateProcessor(
		reflect.TypeFor[apiv3.FelixConfigurationSpec](),
		AllowAnnotations,
		func(node, name string) model.Key { return model.HostConfigKey{Hostname: node, Name: name} },
		func(name string) model.Key { return model.GlobalConfigKey{Name: name} },
		FelixValueConverters,
	)
}

// Convert a slice of ProtoPorts to the string representation required by Felix.
func protoPortSliceToString(value any) any {
	pps := value.([]apiv3.ProtoPort)
	if len(pps) == 0 {
		return "none"
	}
	parts := make([]string, len(pps))
	for i, pp := range pps {
		if pp.Net != "" {
			ip, _, err := cnet.ParseCIDROrIP(pp.Net)
			if err != nil {
				log.WithError(err).Error("Unable to parse CIDR to sync FelixConfiguration data in v1 format")
			}
			if ip.Version() == 6 {
				parts[i] = fmt.Sprintf("%s:[%s]:%d", strings.ToLower(pp.Protocol), pp.Net, pp.Port)
			} else {
				parts[i] = fmt.Sprintf("%s:%s:%d", strings.ToLower(pp.Protocol), pp.Net, pp.Port)
			}
		} else {
			parts[i] = fmt.Sprintf("%s:%d", strings.ToLower(pp.Protocol), pp.Port)
		}
	}
	return strings.Join(parts, ",")
}

// Converts multiple route table ranges to its string config representation.
// e.g. RouteTableRanges{{Min: 0, Max: 250}, {Min: 255, Max: 3000}} => "0-250,255-3000"
func routeTableRangeListToString(value any) any {
	ranges := value.(apiv3.RouteTableRanges)
	rangesStr := make([]string, 0)
	for _, r := range ranges {
		rangesStr = append(rangesStr, fmt.Sprintf("%d-%d", r.Min, r.Max))
	}
	return strings.Join(rangesStr, ",")
}

// Converts a route table range to its string config representation.
// e.g. RouteTableRange{Min: 0, Max: 250} => "0-250"
func routeTableRangeToString(value any) any {
	r := value.(apiv3.RouteTableRange)
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

func healthTimeoutOverridesToString(value any) any {
	htos := value.([]apiv3.HealthTimeoutOverride)
	if len(htos) == 0 {
		return nil
	}
	var parts []string
	for _, hto := range htos {
		parts = append(parts, hto.Name+"="+hto.Timeout.Duration.String())
	}
	return strings.Join(parts, ",")
}

func structToKeyValueString(input any) (string, error) {
	// Get the type and value of the input struct
	v := reflect.ValueOf(input)
	t := reflect.TypeOf(input)

	// Ensure the input is a struct
	if t.Kind() != reflect.Struct {
		return "", fmt.Errorf("input must be a struct")
	}

	// Build the key=value pairs
	var parts []string
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// Handle string fields directly
		if value.Kind() == reflect.String {
			s := value.String()
			if s == "" {
				continue
			}

			parts = append(parts, fmt.Sprintf("%s=%s", field.Name, s))
		}
		// Handle pointer to string fields
		if value.Kind() == reflect.Pointer && value.Type().Elem().Kind() == reflect.String {
			if !value.IsNil() {
				parts = append(parts, fmt.Sprintf("%s=%s", field.Name, value.Elem().String()))
			}
		}

	}

	return strings.Join(parts, ","), nil
}

func bpfConntrackTimeoutsToString(value any) any {
	res, _ := structToKeyValueString(value)
	return res
}

// ExtractFelixConfigFields extracts configuration key-value pairs from a
// FelixConfigurationSpec using reflection, optionally merging annotation-based
// overrides. This is the shared extraction logic used by both the
// configUpdateProcessor (v1 decomposition) and the ConfigBatcher (selector-
// scoped config).
//
// Field names are determined by the confignamev1 tag (or the struct field name
// if unset). Fields tagged confignamev1:"-" are skipped. Nil/empty fields are
// omitted. Value conversion uses FelixValueConverters for special types, with
// fallback to standard stringification matching the configUpdateProcessor.
func ExtractFelixConfigFields(fc *apiv3.FelixConfiguration) map[string]string {
	config := extractSpecFields(&fc.Spec)

	// Apply annotation-based config overrides, consistent with how the
	// configUpdateProcessor handles annotations on default/per-node resources.
	for k, v := range fc.GetAnnotations() {
		if strings.HasPrefix(k, annotationConfigPrefix) {
			config[k[len(annotationConfigPrefix):]] = v
		}
	}

	return config
}

// extractSpecFields iterates over the FelixConfigurationSpec fields and
// converts each set field to a string value.
func extractSpecFields(spec *apiv3.FelixConfigurationSpec) map[string]string {
	config := make(map[string]string)
	specValue := reflect.ValueOf(spec).Elem()
	specType := specValue.Type()

	for i := 0; i < specType.NumField(); i++ {
		fieldInfo := specType.Field(i)
		name := getConfigName(fieldInfo)
		if name == "-" {
			continue
		}

		field := specValue.Field(i)

		// Skip unset (nil pointer) fields and empty strings.
		if field.Kind() == reflect.Pointer {
			if field.IsNil() {
				continue
			}
			field = field.Elem()
		} else {
			if field.Kind() == reflect.String && field.Len() == 0 {
				continue
			}
		}

		value := field.Interface()

		// Convert the value to string using the same converters and type
		// switches as configUpdateProcessor.processAddOrModified.
		var strValue string
		if converter, ok := FelixValueConverters[name]; ok {
			converted := converter(value)
			if converted == nil {
				continue
			}
			strValue = converted.(string)
		} else {
			switch vt := value.(type) {
			case string:
				strValue = vt
			case v1.Duration:
				switch fieldInfo.Tag.Get("configv1timescale") {
				case "milliseconds":
					ms := vt.Duration / time.Millisecond
					remainder := vt.Duration % time.Millisecond
					strValue = fmt.Sprintf("%v", float64(ms)+float64(remainder)/1e6)
				default:
					strValue = fmt.Sprintf("%v", vt.Seconds())
				}
			case []string:
				strValue = strings.Join(vt, ",")
			case map[string]string:
				var kvp strings.Builder
				for k, v := range vt {
					kvp.WriteString(k + "=" + v + ",")
				}
				strValue = kvp.String()
			default:
				strValue = fmt.Sprintf("%v", vt)
			}
		}

		config[name] = strValue
	}
	return config
}
