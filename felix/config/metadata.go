// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
//
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

package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	lcconfig "github.com/projectcalico/calico/libcalico-go/config"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var fieldsToIgnore = set.From(
	// The rekey time is used by the IPsec tests, but it isn't exposed in FelixConfiguration.
	"IPSecRekeyTime",
)

var clusterInfoFields = set.From(
	// Internal settings from ClusterInformation
	"ClusterGUID",
	"ClusterType",
	"CalicoVersion",
	"Variant",
	"CNXVersion",
)

var nodeFields = set.From(
	// Moved to Node.
	"IpInIpTunnelAddr",
	"IPv4VXLANTunnelAddr",
	"IPv6VXLANTunnelAddr",
	"VXLANTunnelMACAddr",
	"VXLANTunnelMACAddrV6",
	"NodeIP",
)

var ConfigGroups = map[string]string{
	"^(Datastore|Typha|Etcd|FelixHostname)": "00 Datastore connection",

	"^Log":                       "00 Process: Logging",
	"^Go":                        "00 Process: Go runtime",
	"^Feature":                   "00 Process: Feature detection/overrides",
	"^Health":                    "00 Process: Health port and timeouts",
	"^Prometheus.*Metrics":       "00 Process: Prometheus metrics",
	"^(Debug|StatsDumpFilePath)": "97 Debug/test-only (generally unsupported)",

	"^(Iptables|Ipsets|KubeNodePortRanges|MaxIpsetSize)": "20 Dataplane: iptables",
	"^Nftables": "21 Dataplane: nftables",
	"^BPF":      "22 Dataplane: eBPF",
	"^Windows":  "23 Dataplane: Windows",
	"^(Openstack|Metadata|EndpointReporting|Reporting)": "25 Dataplane: OpenStack support",
	"^(XDP|GenericXDP)": "25 Dataplane: XDP acceleration for iptables dataplane",

	"^(IPv4|IPv6|)VXLAN": "31 Overlay: VXLAN overlay",
	"^IpInIp":            "32 Overlay: IP-in-IP",
	"^Wireguard":         "33 Overlay: Wireguard",
	"^IPSec":             "34 Overlay: IPSec",

	"^FlowLogs":       "40 Flow logs: file reports",
	"^SyslogReporter": "40 Flow logs: Syslog reports",
	"^(PrometheusReporter|DeletedMetricsRetentionSecs)": "40 Flow logs: Prometheus reports",

	"^DNS":    "50 DNS logs / policy",
	"^L7Logs": "50 L7 logs",

	"^AWS": "60 AWS integration",

	"^Egress":          "70 Egress gateway",
	"^ExternalNetwork": "70 External network support",
	"^Capture":         "80 Packet capture",
	"^TPROXY":          "90 L7 proxy",

	"UsageReporting": "99 Usage reporting",
}

// FieldInfo contains metadata about a Felix configuration parameter, including
// both the config package representation and the v3 API representation.
type FieldInfo struct {
	Group               string
	GroupWithSortPrefix string

	// NameConfigFile is the name of the parameter in the Felix configuration INI file.
	NameConfigFile string
	// NameEnvVar is the name of the environment variable that can be used to set the parameter.
	// Env vars use the config file string format, the name of the env var is case-insensitive.
	NameEnvVar string
	// NameYAML is the name of the field in the FelixConfiguration CustomResource.
	NameYAML string
	// NameGoAPI is the name of the field in the FelixConfiguration v3 Go API structs.
	NameGoAPI string

	// StringSchema is a description of the parameter's format when expressed
	// as a string in the config file or environment variable.  This sometimes
	// differs from the format of the FelixConfiguration field.  For example,
	// Felix may require a comma-delimited list in the env var, but the YAML
	// can represent a list natively.
	StringSchema     string
	StringSchemaHTML string

	// StringDefault is the default value for the parameter in Felix's string
	// format.  This is Felix's baseline default value if the configuration is
	// not set by config file, env var, or FelixConfiguration resource. Note
	// that The operator may apply environment-specific defaults to the
	// FelixConfiguration, making it appear that the default value is different
	// in a particular environment.
	StringDefault string
	// ParsedDefault is the result of parsing StringDefault and pretty-printing
	// it.  For example, the String default for a duration field might be "90",
	// meaning 90 seconds.  That would be converted to a time.Duration, which
	// would pretty-print as "1m30s".
	ParsedDefault string
	// JSON encoding of the ParsedDefault value.
	ParsedDefaultJSON string
	// ParsedType is the type of the field in the Config struct; the type of
	// the ParsedDefault value.
	ParsedType string

	// YAMLType is the type of the field in the FelixConfiguration YAML.
	YAMLType string
	// YAMLSchema is a description of the parameter's format when expressed in
	// YAML in the FelixConfiguration.
	YAMLSchema     string
	YAMLEnumValues []string
	YAMLSchemaHTML string

	// YAMLDefault is the default value for the parameter in FelixConfiguration
	// YAML.
	YAMLDefault string

	// Required is true if the parameter must be set for felix to start.
	Required bool
	// OnParseFailure is the action that Felix takes if the value is invalid.
	// Typically, Felix replaces the value with the default, but some important
	// fields trigger Felix to exit.
	OnParseFailure ParseFailureAction
	// AllowedConfigSources indicates where Felix will accept the
	// configuration from.  For example, datastore-related fields must be set
	// locally, they cannot come from the datastore.
	AllowedConfigSources AllowedConfigSources

	// Description is a human-readable description of the parameter, largely
	// derived from the CRD.
	Description     string
	DescriptionHTML string

	// UserEditable is true if the parameter is intended to be set by the user.
	// Some fields are auto-populated from the cluster or node identity.  They
	// are "config" to Felix, but they are set by another component.
	UserEditable bool

	// GoType is the type of the field in the FelixConfiguration Go API structs.
	GoType string
}

type ParseFailureAction string

const (
	ParseFailureActionExit               ParseFailureAction = "Exit"
	ParseFailureActionReplaceWithDefault ParseFailureAction = "ReplaceWithDefault"
)

type AllowedConfigSources string

const (
	AllowedConfigSourcesAll       AllowedConfigSources = "All"
	AllowedConfigSourcesLocalOnly AllowedConfigSources = "LocalOnly"
)

// CombinedFieldInfo loads the metadata for Felix's configuration parameters.
// it combines the metadata from Felix's config package with the metadata from
// the v3 API structs.
func CombinedFieldInfo() ([]*FieldInfo, error) {
	var params []*FieldInfo

	// Load the parameters from Felix's config package.
	params, _ = loadFelixParamMetadata(params)

	// Most CRD fields have the same name as the name in the Config struct
	// but there are some historical exceptions.  We store the exception
	// mapping in the v3 API structs, so we index those by felix name.
	felixNameToV3FieldInfo, err := loadV3APIMetadata()
	if err != nil {
		return nil, err
	}

	// Combine the two...
	params = updateParamsWithV3Info(params, felixNameToV3FieldInfo)

	for _, pm := range params {
		if pm.YAMLSchema == "Integer." && strings.HasPrefix(pm.StringSchema, "Integer") {
			// String schema tends to have the ranges, which are missing from the YAML.
			pm.YAMLSchema = pm.StringSchema
		}
		if pm.GoType == "*numorstring.Port" {
			// The Port type has its own string encoding.
			pm.YAMLSchema = "Port range: either an integer in [0,65535] or a string, representing a range, in format `n:m`"
		}

		pm.StringSchemaHTML = convertSchemaToHTML(pm.StringSchema)
		pm.YAMLSchemaHTML = convertSchemaToHTML(pm.YAMLSchema)
		pm.DescriptionHTML = convertDescriptionToHTML(pm.Description)

		if pm.NameYAML != "" && pm.YAMLDefault == "" {
			switch pm.NameConfigFile {
			case "BPFForceTrackPacketsFromIfaces", "KubeNodePortRanges",
				"FailsafeInboundHostPorts", "FailsafeOutboundHostPorts":
				// These fields have complex types but the v3 types and the
				// Config types are either the same, or close enough that
				// the JSON is the same.
				pm.YAMLDefault = pm.ParsedDefaultJSON
			default:
				switch pm.ParsedType {
				case "*bool", "bool", "*int", "int", "uint32", "string", "net.IP", "*regexp.Regexp", "[]*regexp.Regexp":
					// These types are simple enough that the v3 and Config
					// types have compatible defaults.
					if len(pm.YAMLEnumValues) > 0 {
						// If the type is an enum, use the enum constants from
						// the YAML since they are more likely to have the
						// correct case.  For example, `Info` instead of `INFO`.
						for _, ev := range pm.YAMLEnumValues {
							if strings.EqualFold(ev, pm.StringDefault) {
								pm.YAMLDefault = ev
								break
							}
						}
					}
					if pm.YAMLDefault == "" {
						pm.YAMLDefault = pm.StringDefault
					}
				case "time.Duration":
					// The YAML form of a duration is the Go duration format.
					// For example, "1m30s".
					pm.YAMLDefault = pm.ParsedDefault
				case "numorstring.Port":
					if pm.GoType == "*numorstring.Port" {
						// The Port type has its own string encoding.
						pm.YAMLDefault = pm.ParsedDefault
					}
				}
			}
		}
	}

	// Sort for consistency.
	slices.SortFunc(params, func(a, b *FieldInfo) int {
		if a.NameConfigFile < b.NameConfigFile {
			return -1
		} else if a.NameConfigFile > b.NameConfigFile {
			return 1
		}
		return 0
	})

	return params, nil
}

var backtickRegex = regexp.MustCompile("`([^`]+)`")

func convertDescriptionToHTML(description string) string {
	// The description is basically simple markdown:
	// - Single newlines should be ignored.
	// - Double newlines should be converted to <p>.
	// - Backticks should be converted to <code>.
	description = escapeHTML(description)
	description = "<p>" + strings.ReplaceAll(description, "\n\n", "</p>\n<p>") + "</p>"
	description = convertBackticksToHTML(description)
	return description
}

func convertSchemaToHTML(description string) string {
	// The schema is simpler than the description, we only need to handle
	// backticks.
	description = escapeHTML(description)
	// 2^63 is common in int ranges, make it look nicer.
	description = strings.ReplaceAll(description, "2^63", "2<sup>63</sup>")
	description = convertBackticksToHTML(description)
	return description
}

func convertBackticksToHTML(description string) string {
	return backtickRegex.ReplaceAllString(description, "<code>$1</code>")
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func loadFelixParamMetadata(params []*FieldInfo) ([]*FieldInfo, error) {
	comments, err := loadConfigParamComments()
	if err != nil {
		return nil, err
	}

	for _, param := range Params() {
		metadata := param.GetMetadata()

		if fieldsToIgnore.Contains(metadata.Name) {
			continue
		}

		var parsedDefault string
		// On PPC (under Qemu), *regexp.Regexp has a String() method that
		// sometimes hits SIGSEGV on a nil pointer.  (On x86, the String()
		// method panics instead and the panic is recovered by fmt.Sprint().)
		if safeIsNil(metadata.Default) {
			parsedDefault = ""
		} else {
			parsedDefault = fmt.Sprint(metadata.Default)
			if parsedDefault == "<nil>" {
				parsedDefault = ""
			}
		}
		parsedDefaultJSON, err := json.Marshal(metadata.Default)
		if err != nil {
			logrus.WithError(err).WithField("name", metadata.Name).Error("Failed to marshal default value to JSON")
		}
		pm := &FieldInfo{
			NameConfigFile:       metadata.Name,
			Group:                strings.TrimLeft(groupForName(metadata.Name), " 1234567890"),
			GroupWithSortPrefix:  groupForName(metadata.Name),
			NameEnvVar:           fmt.Sprintf("FELIX_%s", metadata.Name),
			StringDefault:        metadata.DefaultString,
			ParsedDefault:        parsedDefault,
			ParsedDefaultJSON:    string(parsedDefaultJSON),
			ParsedType:           metadata.Type,
			Required:             metadata.NonZero,
			AllowedConfigSources: AllowedConfigSourcesAll,
			StringSchema:         param.SchemaDescription(),
			UserEditable:         true,
			Description:          tweakDescription(metadata.Name, comments[metadata.Name], false),
		}
		if metadata.DieOnParseFailure {
			pm.OnParseFailure = ParseFailureActionExit
		} else {
			pm.OnParseFailure = ParseFailureActionReplaceWithDefault
		}
		if metadata.Local {
			pm.AllowedConfigSources = AllowedConfigSourcesLocalOnly
		}

		params = append(params, pm)
	}
	return params, nil
}

func safeIsNil(v any) bool {
	if v == nil {
		// The nil interface, no type or value.
		return true
	}
	if reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil() {
		// Typed nil.
		return true
	}
	return false
}

//go:embed config_params.go
var configParamsFile []byte

func loadConfigParamComments() (map[string]string, error) {
	fileSet := token.NewFileSet()
	fileAST, err := parser.ParseFile(fileSet, "config_params.go", configParamsFile, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	pkg, err := doc.NewFromFiles(fileSet, []*ast.File{fileAST}, "")
	if err != nil {
		return nil, err
	}

	var docType *doc.Type
	const typeName = "Config"
	for _, t := range pkg.Types {
		if t.Name == typeName {
			docType = t
			break
		}
	}
	if docType == nil {
		return nil, err
	}

	comments := map[string]string{}
	ast.Inspect(docType.Decl, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Field:
			name := node.Names[0].Name
			comment := node.Doc.Text()
			comments[name] = comment
		}
		return true
	})

	return comments, nil
}

func groupForName(name string) string {
	for pattern, group := range ConfigGroups {
		if matched, _ := regexp.MatchString(pattern, name); matched {
			return group
		}
	}
	return "10 Dataplane: Common"
}

func loadV3APIMetadata() (map[string]YAMLInfo, error) {
	out := make(map[string]YAMLInfo)

	// Some data we need to get from teh struct directly (namely, the Felix
	// parameter name mapping).
	yamlNameToStructInfo := parseStruct()

	// The rest is easiest to get from the CRD, where kubebuilder has already
	// done the hard work for us.
	crd, err := lcconfig.LoadCRD("crd.projectcalico.org", "felixconfigurations")
	if err != nil {
		return nil, fmt.Errorf("failed to load CRD: %v", err)
	}

	if len(crd.Spec.Versions) != 1 {
		return nil, fmt.Errorf("not supported: CRD should have single version")
	}
	spec := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"]
	for yamlName, prop := range spec.Properties {
		si, ok := yamlNameToStructInfo[yamlName]
		if !ok {
			return nil, fmt.Errorf("no struct info for CRD field %s", yamlName)
		}
		info := YAMLInfo{
			YAMLName:    yamlName,
			Description: tweakDescription(si.GoName, prop.Description, false),
		}
		info.GoName = si.GoName
		info.GoType = si.GoType
		info.V1Name = si.V1Name

		if prop.Type != "" {
			info.YAMLType = prop.Type
		} else if len(prop.AnyOf) > 0 {
			// Int or string?
			var types []string
			for _, anyOf := range prop.AnyOf {
				if anyOf.Type != "" {
					types = append(types, anyOf.Type)
				}
			}
			if len(types) >= 1 {
				info.YAMLType = strings.Join(types, " or ")
			}
		}
		info.Schema, info.EnumValues = v3TypesToDescription(si, prop)

		out[info.V1Name] = info
		out[yamlName] = info
	}

	return out, nil
}

// Regex to extract enum constants from the standard enum regex. Example: ^(?i)(Drop|Accept|Return)?$
var enumRegex = regexp.MustCompile(`^\^?(\(\?i\))?\(([\w|]+)\)\??\$?$`)

func v3TypesToDescription(si StructInfo, prop v1.JSONSchemaProps) (infoSchema string, enumConsts []string) {
	pattern := prop.Pattern
	switch si.GoType {
	case "*bool", "bool":
		infoSchema = "Boolean."
	case "*int", "int":
		infoSchema = "Integer."
	case "*uint32":
		infoSchema = "Unsigned 32-bit integer."
	case "*string", "string":
		enumConsts, infoSchema = parsePattern(pattern)
	case "*v1.Duration", "v1.Duration":
		infoSchema = "Duration string, for example `1m30s123ms` or `1h5m`."
	case "*v3.RouteTableRange", "v3.RouteTableRange":
		infoSchema = "Route table range: `{min:<n>, max<m>}`."
	case "*v3.RouteTableRanges", "v3.RouteTableRanges":
		infoSchema = "List of route table ranges: `[{min:<n>, max<m>}, ...]`."
	case "*[]numorstring.Port":
		infoSchema = "List of ports: `[<port>, ...]` where `<port>` is a port number (integer) or range (string), " +
			"for example `80`, `8080:8089`."
	case "*[]v3.ProtoPort":
		infoSchema = "List of protocol/port objects with optional CIDR match: `[{protocol: \"TCP|UDP\", port: <port>, net: \"<cidr>\"}, ...]`."
	case "*[]string", "[]string":
		if strings.Contains(si.GoValidation, "cidrs") {
			infoSchema = "List of CIDRs: `[\"<cidr>\", ...]`."
		} else if strings.Contains(si.GoValidation, "ifaceFilterSlice") {
			infoSchema = "List of interface names (may use `+` as a wildcard: `[\"<name>\", ...]`."
		} else {
			infoSchema = "List of strings: `[\"<string>\", ...]`."
		}
	case "[]v3.HealthTimeoutOverride":
		infoSchema = "List of health timeout overrides: `[{name: \"<name>\", timeout: \"<duration>\"}, ...]` " +
			"where `<duration>` is in the Go duration format, for example `1m30s`."
	default:
		if pattern != "" {
			enumConsts, infoSchema = parsePattern(pattern)
		}
	}
	if len(prop.Enum) > 0 {
		var parts []string
		for _, e := range prop.Enum {
			var enumConst any
			err := json.Unmarshal(e.Raw, &enumConst)
			if err != nil {
				logrus.WithError(err).WithField("enum", e.Raw).Fatal("Failed to unmarshal enum constant.")
			}
			enumConsts = append(enumConsts, fmt.Sprint(enumConst))
			parts = append(parts, fmt.Sprintf("`%s`", e.Raw))
		}
		sort.Strings(parts)
		enumConsts = parts
		infoSchema = fmt.Sprintf("One of: %s.", strings.Join(parts, ", "))
	}
	sort.Strings(enumConsts)
	return
}

func parsePattern(pattern string) (enumConsts []string, infoSchema string) {
	if pattern != "" && pattern != "^.*" {
		if m := enumRegex.FindStringSubmatch(pattern); m != nil {
			// Enum regex, parse out the constants.
			parts := strings.Split(m[2], "|")
			sort.Strings(parts)
			for i, p := range parts {
				enumConsts = append(enumConsts, p)
				parts[i] = fmt.Sprintf("`%s`", p)
			}
			infoSchema = fmt.Sprintf("One of: %s.", strings.Join(parts, ", "))
		} else {
			infoSchema = fmt.Sprintf("String matching the regular expression `%s`.", pattern)
		}
	} else {
		infoSchema = "String."
	}
	return
}

func updateParamsWithV3Info(params []*FieldInfo, felixNameToCRDFieldInfo map[string]YAMLInfo) []*FieldInfo {
	for _, pm := range params {
		if info, ok := felixNameToCRDFieldInfo[pm.NameConfigFile]; ok {
			pm.NameGoAPI = info.GoName
			pm.Description = info.Description
			pm.NameYAML = info.YAMLName
			pm.GoType = info.GoType
			pm.YAMLType = info.YAMLType
			pm.YAMLSchema = info.Schema
			pm.YAMLEnumValues = info.EnumValues
		} else if clusterInfoFields.Contains(pm.NameConfigFile) {
			pm.UserEditable = false
			pm.Description = "Auto-populated cluster identity information (not intended to be edited by the user), learned from the `ClusterInformation` resource."
			pm.Group = "98 Cluster identity (usually read-only)"
		} else if nodeFields.Contains(pm.NameConfigFile) {
			pm.UserEditable = false
			pm.Description = "Node specific configuration, learned from the `Node` resource (rather than the `FelixConfiguration` custom resource)."
			pm.Group = "98 Node identity (usually read-only)"
		} else if pm.AllowedConfigSources != AllowedConfigSourcesLocalOnly && strings.HasPrefix(pm.NameConfigFile, "Debug") {
			pm.Description = "Unsupported diagnostic setting, used when testing Felix.  Not exposed in `FelixConfiguration`."
		} else if pm.AllowedConfigSources != AllowedConfigSourcesLocalOnly {
			logrus.Panicf("No CRD info for %s.  Bug in the CRD mapping?\n", pm.NameConfigFile)
		}
	}
	return params
}

type YAMLInfo struct {
	YAMLName    string
	Description string
	Schema      string
	GoName      string
	GoType      string
	V1Name      string
	YAMLType    string
	EnumValues  []string
}

var trimDefaultRegex = regexp.MustCompile(`(?i)\[default[^]]+]`)
var replaceNewlinesRegex = regexp.MustCompile(`\s*\n\s*`)
var multiSpaceRegex = regexp.MustCompile(` +`)

func tweakDescription(name, description string, doubleNewlines bool) string {
	description = strings.TrimSpace(description)
	if description == "" {
		return ""
	}
	description = strings.TrimPrefix(description, name)
	description = strings.TrimSpace(description)
	description = strings.TrimLeft(description, ",:")
	description = strings.TrimSpace(description)
	description = strings.TrimPrefix(description, "is ")
	description = trimDefaultRegex.ReplaceAllString(description, "")
	description = strings.TrimSpace(description)
	description = strings.ToUpper(description[0:1]) + description[1:]
	if doubleNewlines {
		description = replaceNewlinesRegex.ReplaceAllString(description, "\n\n")
	}
	description = multiSpaceRegex.ReplaceAllString(description, " ")
	description = strings.TrimSpace(description)
	switch description[len(description)-1] {
	case '.', '!', '?':
		break
	case ')':
		if !strings.HasSuffix(description, ".)") {
			description = description + "."
		}
	default:
		description = description + "."
	}
	return description
}

type StructInfo struct {
	GoName       string
	YAMLName     string
	V1Name       string
	GoType       string
	GoValidation string
}

func parseStruct() map[string]StructInfo {
	out := make(map[string]StructInfo)

	var spec v3.FelixConfigurationSpec
	t := reflect.TypeOf(spec)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		goName := field.Name
		yamlName := strings.Split(field.Tag.Get("json"), ",")[0]
		v1Name := goName
		if tag := field.Tag.Get("confignamev1"); tag != "" {
			v1Name = tag
		}

		out[yamlName] = StructInfo{
			GoName:   goName,
			YAMLName: yamlName,
			V1Name:   v1Name,

			GoType:       field.Type.String(),
			GoValidation: field.Tag.Get("validate"),
		}
	}

	return out
}
