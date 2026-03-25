// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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

package v3

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	wireguard "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/go-playground/validator.v9"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	calicoconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var validate *validator.Validate

const (
	// Maximum size of annotations.
	totalAnnotationSizeLimitB int64 = 256 * (1 << 10) // 256 kB

	// using 0xFFFFFFFF tables would require too much computation, so the total number of designated tables is capped at 0xFFFF
	routeTableRangeMaxTables uint32 = 0xffff

	globalSelector = "global()"
)

var (
	nameLabelFmt     = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	nameSubdomainFmt = nameLabelFmt + "(\\." + nameLabelFmt + ")*"

	// All resource names must follow the subdomain name format.  Some resources we impose
	// more restrictive naming requirements.
	nameRegex = regexp.MustCompile("^" + nameSubdomainFmt + "$")

	// Tiers must have simple names with no dots, since they appear as sub-components of other
	// names.
	tierNameRegex = regexp.MustCompile("^" + nameLabelFmt + "$")

	containerIDFmt   = "[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?"
	containerIDRegex = regexp.MustCompile("^" + containerIDFmt + "$")

	// NetworkPolicy names must either be a simple DNS1123 label format (nameLabelFmt), or
	// nameLabelFmt.nameLabelFmt (with a single dot), or
	// must be the standard name format (nameRegex) prefixed with "knp.default" or "ossg.default".
	networkPolicyNameRegex = regexp.MustCompile("^((" + nameLabelFmt + ")(\\." + nameLabelFmt + ")?|((?:knp|ossg)\\.default\\.(" + nameSubdomainFmt + ")))$")

	// GlobalNetworkPolicy names must be a simple DNS1123 label format (nameLabelFmt) or
	// have a single dot.
	globalNetworkPolicyNameRegex = regexp.MustCompile("^(" + nameLabelFmt + "\\.)?" + nameLabelFmt + "$")

	// Hostname  have to be valid ipv4, ipv6 or strings up to 64 characters.
	prometheusHostRegexp = regexp.MustCompile(`^[a-zA-Z0-9:._+-]{1,64}$`)

	interfaceRegex                = regexp.MustCompile("^[a-zA-Z0-9_.-]{1,15}$")
	bgpFilterInterfaceRegex       = regexp.MustCompile("^[a-zA-Z0-9_.*-]{1,15}$")
	bgpFilterPrefixLengthV4       = regexp.MustCompile("^([0-9]|[12][0-9]|3[0-2])$")
	bgpFilterPrefixLengthV6       = regexp.MustCompile("^([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$")
	ignoredInterfaceRegex         = regexp.MustCompile("^[a-zA-Z0-9_.*-]{1,15}$")
	ifaceFilterRegex              = regexp.MustCompile("^[a-zA-Z0-9:._+-]{1,15}$")
	protocolRegex                 = regexp.MustCompile("^(TCP|UDP|ICMP|ICMPv6|SCTP|UDPLite)$")
	ipTypeRegex                   = regexp.MustCompile("^(CalicoNodeIP|InternalIP|ExternalIP)$")
	standardCommunity             = regexp.MustCompile(`^(\d+):(\d+)$`)
	largeCommunity                = regexp.MustCompile(`^(\d+):(\d+):(\d+)$`)
	number                        = regexp.MustCompile(`(\d+)`)
	IPv4PortFormat                = regexp.MustCompile(`^(\d+).(\d+).(\d+).(\d+):(\d+)$`)
	IPv6PortFormat                = regexp.MustCompile(`^\[[0-9a-fA-F:.]+\]:(\d+)$`)
	reasonString                  = "Reason: "
	poolUnstictCIDR               = "IP pool CIDR is not strictly masked"
	overlapsV4LinkLocal           = "IP pool range overlaps with IPv4 Link Local range 169.254.0.0/16"
	overlapsV6LinkLocal           = "IP pool range overlaps with IPv6 Link Local range fe80::/10"
	protocolPortsMsg              = "rules that specify ports must set protocol to TCP or UDP or SCTP"
	protocolSingleOrRangePortsMsg = "rules with numeric port or port range must set protocol to TCP or UDP or SCTP"
	globalSelectorOnly            = fmt.Sprintf("%v cannot be combined with other selectors", globalSelector)

	SourceAddressRegex = regexp.MustCompile("^(UseNodeIP|None)$")

	ipv4LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	ipv6LinkLocalNet = net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}
)

// Validate validates the supplied structure according to registered field and
// structure validators, plus CRD schema constraints (OpenAPI + CEL). For
// runtime.Object values, CRD schema defaults are applied in-place before
// validation so that omitted fields with CRD defaults are populated the same
// way the Kubernetes API server would on admission.
func Validate(current any) error {
	var verr errors.ErrorValidation

	// Perform field-only validation first, that way the struct validators can assume
	// individual fields are valid format.
	if err := validate.Struct(current); err != nil {
		verr = convertError(err)
	}

	// Apply CRD schema defaults and then run CRD validation rules (OpenAPI
	// schema constraints + CEL x-kubernetes-validations). In Kubernetes
	// datastore mode, the API server handles both defaulting and validation
	// on admission. In etcd mode there is no API server, so we do both here.
	if rObj, ok := current.(runtime.Object); ok {
		if crdErrs := defaultAndValidateCRD(context.Background(), rObj, nil); len(crdErrs) > 0 {
			for _, e := range crdErrs {
				name := e.Field
				if name == "" || name == "<nil>" {
					name = resolveKind(rObj)
				}
				verr.ErroredFields = append(verr.ErroredFields, errors.ErroredField{
					Name:   name,
					Reason: e.Detail,
				})
			}
		}
	}

	if len(verr.ErroredFields) > 0 {
		return verr
	}
	return nil
}

func convertError(err error) errors.ErrorValidation {
	verr := errors.ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErroredFields = append(verr.ErroredFields,
			errors.ErroredField{
				Name:   f.StructField(),
				Value:  f.Value(),
				Reason: extractReason(f),
			})
	}
	return verr
}

func init() {
	// Initialise static data.
	validate = validator.New()

	// Validators for internal API types that have no backing CRD.
	// These must remain as Go validators since CRD schema validation
	// cannot cover them.
	registerFieldValidator("createDefaultHostEndpoint", validateCreateDefaultHostEndpoint)
	registerFieldValidator("ipType", validateIPType)

	// Validators for fields on CRD-backed types where the constraint is
	// not expressible via CRD schema annotations (e.g., complex format
	// checks, cross-field logic handled in Go, or fields on internal
	// sub-structs shared with non-CRD types).
	registerFieldValidator("interface", validateInterface)
	registerFieldValidator("bgpFilterInterface", validateBGPFilterInterface)
	registerFieldValidator("bgpFilterPrefixLengthV4", validateBGPFilterPrefixLengthV4)
	registerFieldValidator("bgpFilterPrefixLengthV6", validateBGPFilterPrefixLengthV6)
	registerFieldValidator("ignoredInterface", validateIgnoredInterface)
	registerFieldValidator("name", validateName)
	registerFieldValidator("containerID", validateContainerID)
	registerFieldValidator("selector", validateSelector)
	registerFieldValidator("labels", validateLabels)
	registerFieldValidator("bpfLogFilters", validateBPFLogFilters)
	registerFieldValidator("portName", validatePortName)
	registerFieldValidator("mustBeNil", validateMustBeNil)
	registerFieldValidator("mustBeFalse", validateMustBeFalse)
	registerFieldValidator("ifaceFilter", validateIfaceFilter)
	registerFieldValidator("interfaceSlice", validateInterfaceSlice)
	registerFieldValidator("ifaceFilterSlice", validateIfaceFilterSlice)
	registerFieldValidator("mac", validateMAC)
	registerFieldValidator("keyValueList", validateKeyValueList)
	registerFieldValidator("prometheusHost", validatePrometheusHost)
	registerFieldValidator("regexp", validateRegexp)
	registerFieldValidator("wireguardPublicKey", validateWireguardPublicKey)
	registerFieldValidator("IP:port", validateIPPort)
	registerFieldValidator("reachableBy", validateReachableByField)

	// Register network validators (i.e. validating a correctly masked CIDR).  Also
	// accepts an IP address without a mask (assumes a full mask).
	registerFieldValidator("netv4", validateIPv4Network)
	registerFieldValidator("netv6", validateIPv6Network)
	registerFieldValidator("net", validateIPNetwork)
	registerFieldValidator("ipv4", validateIPv4)
	registerFieldValidator("ipv6", validateIPv6)

	// Override the default CIDR validator.  Validates an arbitrary CIDR (does not
	// need to be correctly masked).  Also accepts an IP address without a mask.
	registerFieldValidator("cidrv4", validateCIDRv4)
	registerFieldValidator("cidrv6", validateCIDRv6)
	registerFieldValidator("cidr", validateCIDR)
	registerFieldValidator("cidrs", validateCIDRs)

	registerStructValidator(validate, validateProtocol, numorstring.Protocol{})
	registerStructValidator(validate, validateProtoPort, api.ProtoPort{})
	registerStructValidator(validate, validatePort, numorstring.Port{})
	registerStructValidator(validate, validateEndpointPort, api.EndpointPort{})
	registerStructValidator(validate, validateWorkloadEndpointPort, internalapi.WorkloadEndpointPort{})
	registerStructValidator(validate, validateIPNAT, internalapi.IPNAT{})
	registerStructValidator(validate, validateIPPoolSpec, api.IPPoolSpec{})
	registerStructValidator(validate, validateNodeSpec, internalapi.NodeSpec{})
	registerStructValidator(validate, validateIPAMConfigSpec, api.IPAMConfigurationSpec{})
	registerStructValidator(validate, validateObjectMeta, metav1.ObjectMeta{})
	registerStructValidator(validate, validateTier, api.Tier{})
	registerStructValidator(validate, validateHTTPRule, api.HTTPMatch{})
	registerStructValidator(validate, validateFelixConfigSpec, api.FelixConfigurationSpec{})
	registerStructValidator(validate, validateWorkloadEndpointSpec, internalapi.WorkloadEndpointSpec{})
	registerStructValidator(validate, validateRule, api.Rule{})
	registerStructValidator(validate, validateEntityRule, api.EntityRule{})
	registerStructValidator(validate, validateBGPPeerSpec, api.BGPPeerSpec{})
	registerStructValidator(validate, validateNetworkPolicy, api.NetworkPolicy{})
	registerStructValidator(validate, validateGlobalNetworkPolicy, api.GlobalNetworkPolicy{})
	registerStructValidator(validate, validateStagedGlobalNetworkPolicy, api.StagedGlobalNetworkPolicy{})
	registerStructValidator(validate, validateStagedNetworkPolicy, api.StagedNetworkPolicy{})
	registerStructValidator(validate, validateStagedKubernetesNetworkPolicy, api.StagedKubernetesNetworkPolicy{})
	registerStructValidator(validate, validateGlobalNetworkSet, api.GlobalNetworkSet{})
	registerStructValidator(validate, validateNetworkSet, api.NetworkSet{})
	registerStructValidator(validate, validateRuleMetadata, api.RuleMetadata{})
	registerStructValidator(validate, validateBGPConfigurationSpec, api.BGPConfigurationSpec{})
	registerStructValidator(validate, validateBlockAffinitySpec, api.BlockAffinitySpec{})
	registerStructValidator(validate, validateHealthTimeoutOverride, api.HealthTimeoutOverride{})
}

// reason returns the provided error reason prefixed with an identifier that
// allows the string to be used as the field tag in the validator and then
// re-extracted as the reason when the validator returns a field error.
func reason(r string) string {
	return reasonString + r
}

// extractReason extracts the error reason from the field tag in a validator
// field error (if there is one).
func extractReason(e validator.FieldError) string {
	if after, ok := strings.CutPrefix(e.Tag(), reasonString); ok {
		return after
	}
	return fmt.Sprintf("%sfailed to validate Field: %s because of Tag: %s ",
		reasonString,
		e.Field(),
		e.Tag(),
	)
}

func registerFieldValidator(key string, fn validator.Func) {
	// We need to register the field validation funcs for all validators otherwise
	// the validator panics on an unknown validation type.
	validate.RegisterValidation(key, fn)
}

func registerStructValidator(validator *validator.Validate, fn validator.StructLevelFunc, t ...any) {
	validator.RegisterStructValidation(fn, t...)
}

func validateInterface(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate interface: %s", s)
	return s == "*" || interfaceRegex.MatchString(s)
}

func validateBGPFilterInterface(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate BGPFilter rule interface: %s", s)
	return s == "*" || bgpFilterInterfaceRegex.MatchString(s)
}

func validateBGPFilterPrefixLengthV4(fl validator.FieldLevel) bool {
	s := fmt.Sprint(fl.Field())
	log.Debugf("Validate BGPFilter PrefixLength v4: %s", s)
	return s == "*" || bgpFilterPrefixLengthV4.MatchString(s)
}

func validateBGPFilterPrefixLengthV6(fl validator.FieldLevel) bool {
	s := fmt.Sprint(fl.Field())
	log.Debugf("Validate BGPFilter PrefixLength v6: %s", s)
	return s == "*" || bgpFilterPrefixLengthV6.MatchString(s)
}

func validateIgnoredInterface(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate ignored interface name: %s", s)
	return s != "*" && ignoredInterfaceRegex.MatchString(s)
}

func validateIfaceFilter(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate Interface Filter : %s", s)
	return ifaceFilterRegex.MatchString(s)
}

func validateInterfaceSlice(fl validator.FieldLevel) bool {
	slice := fl.Field().Interface().([]string)
	log.Debugf("Validate Interface Slice : %v", slice)

	for _, val := range slice {
		match := interfaceRegex.MatchString(val)
		if !match {
			return false
		}
	}

	return true
}

func validateIfaceFilterSlice(fl validator.FieldLevel) bool {
	slice := fl.Field().Interface().([]string)
	log.Debugf("Validate Interface Filter Slice : %v", slice)

	for _, val := range slice {
		// Important: must use ifaceFilterRegex to allow interface wildcard match
		// e.g. "docker+" which the standard interfaceRegex does not accommodate.
		match := ifaceFilterRegex.MatchString(val)
		if !match {
			return false
		}
	}

	return true
}

func validateRegexp(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate regexp: %s", s)
	_, err := regexp.Compile(s)
	return err == nil
}

func validateIPType(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate IPType: %s", s)
	return ipTypeRegex.MatchString(s)
}

func validateWireguardPublicKey(fl validator.FieldLevel) bool {
	k := fl.Field().String()
	log.Debugf("Validate Wireguard public-key %s", k)
	_, err := wireguard.ParseKey(k)
	return err == nil
}

func validateName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate name: %s", s)
	return nameRegex.MatchString(s)
}

func validateContainerID(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate containerID: %s", s)
	return containerIDRegex.MatchString(s)
}

func validatePrometheusHost(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate prometheusHost: %s", s)
	return prometheusHostRegexp.MatchString(s)
}

func validatePortName(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate port name: %s", s)
	return len(s) != 0 && len(k8svalidation.IsValidPortName(s)) == 0
}

func validateMustBeNil(fl validator.FieldLevel) bool {
	log.WithField("field", fl.Field().String()).Debugf("Validate field must be nil")
	return fl.Field().IsNil()
}

func validateMustBeFalse(fl validator.FieldLevel) bool {
	log.WithField("field", fl.Field().String()).Debugf("Validate field must be false")
	return !fl.Field().Bool()
}

func validateCreateDefaultHostEndpoint(fl validator.FieldLevel) bool {
	s := api.DefaultHostEndpointMode(fl.Field().String())
	return s == api.DefaultHostEndpointsEnabled || s == api.DefaultHostEndpointsDisabled
}

func RegexValidator(desc string, rx *regexp.Regexp) func(fl validator.FieldLevel) bool {
	return func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		log.Debugf("Validate %s: %s", desc, s)
		return rx.MatchString(s)
	}
}

func validateMAC(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate MAC Address: %s", s)

	if err := ValidateMAC(s); err != nil {
		return false
	}
	return true
}

func ValidateMAC(mac string) error {
	_, err := net.ParseMAC(mac)
	return err
}

func validateBPFLogFilters(fl validator.FieldLevel) bool {
	log.Debugf("Validate Felix BPF log level: %s", fl.Field().String())

	m, ok := fl.Field().Interface().(map[string]string)
	if !ok {
		return false
	}

	for k := range m {
		if !interfaceRegex.MatchString(k) {
			return false
		}
	}

	return true
}

func validateSelector(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate selector: %s", s)

	// We use the selector parser to validate a selector string.
	err := selector.Validate(s)
	if err != nil {
		log.Debugf("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateTag(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	log.Debugf("Validate tag: %s", s)
	return nameRegex.MatchString(s)
}

func validateLabels(fl validator.FieldLevel) bool {
	labels := fl.Field().Interface().(map[string]string)
	for k, v := range labels {
		if len(k8svalidation.IsQualifiedName(k)) != 0 {
			return false
		}
		if len(k8svalidation.IsValidLabelValue(v)) != 0 {
			return false
		}
	}
	return true
}

func validateProtocol(structLevel validator.StructLevel) {
	p := structLevel.Current().Interface().(numorstring.Protocol)
	log.Debugf("Validate protocol: %v %s %d", p.Type, p.StrVal, p.NumVal)

	// The protocol field may be an integer 1-255 (i.e. not 0), or one of the valid protocol
	// names.
	if num, err := p.NumValue(); err == nil {
		if num == 0 {
			structLevel.ReportError(reflect.ValueOf(p.NumVal),
				"Protocol", "", reason("protocol number invalid"), "")
		}
	} else if !protocolRegex.MatchString(p.String()) {
		structLevel.ReportError(reflect.ValueOf(p.String()),
			"Protocol", "", reason("protocol name invalid"), "")
	}
}

// validateIPv4Network validates the field is a valid (strictly masked) IPv4 network.
// An IP address is valid, and assumed to be fully masked (i.e /32)
func validateIPv4Network(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv4 network: %s", n)
	err := ValidateIPv4Network(n)
	if err != nil {
		return false
	}
	return true
}

func ValidateIPv4Network(addr string) error {
	ipa, ipn, err := cnet.ParseCIDROrIP(addr)
	if err != nil {
		return err
	}
	// Check for the correct version and that the CIDR is correctly masked (by comparing the
	// parsed IP against the IP in the parsed network).
	if ipa.Version() == 4 && ipn.IP.String() == ipa.String() {
		return nil
	}
	return fmt.Errorf("Invalid IPv4 network %s", addr)
}

// validateIPv6Network validates the field is a valid (strictly masked) IPv6 network.
// An IP address is valid, and assumed to be fully masked (i.e /128)
func validateIPv6Network(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv6 network: %s", n)
	err := ValidateIPv6Network(n)
	if err != nil {
		return false
	}
	return true
}

func ValidateIPv6Network(addr string) error {
	ipa, ipn, err := cnet.ParseCIDROrIP(addr)
	if err != nil {
		return err
	}
	// Check for the correct version and that the CIDR is correctly masked (by comparing the
	// parsed IP against the IP in the parsed network).
	if ipa.Version() == 6 && ipn.IP.String() == ipa.String() {
		return nil
	}
	return fmt.Errorf("Invalid IPv6 network %s", addr)
}

// validateIPNetwork validates the field is a valid (strictly masked) IP network.
// An IP address is valid, and assumed to be fully masked (i.e /32 or /128)
func validateIPNetwork(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IP network: %s", n)
	ipa, ipn, err := cnet.ParseCIDROrIP(n)
	if err != nil {
		return false
	}

	// Check  that the CIDR is correctly masked (by comparing the parsed IP against
	// the IP in the parsed network).
	return ipn.IP.String() == ipa.String()
}

// validateCIDRv4 validates the field is a valid (not strictly masked) IPv4 network.
func validateCIDRv4(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv4 network: %s", n)
	err := ValidateCIDRv4(n)
	if err != nil {
		return false
	}
	return true
}

func ValidateCIDRv4(cidr string) error {
	ipa, _, err := cnet.ParseCIDROrIP(cidr)
	if err != nil {
		return err
	}
	if ipa.Version() == 4 {
		return nil
	}
	return fmt.Errorf("Invalid IPv4 CIDR: %s", cidr)
}

// validateCIDRv6 validates the field is a valid (not strictly masked) IPv6 network.
func validateCIDRv6(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv6 network: %s", n)
	err := ValidateCIDRv6(n)
	if err != nil {
		return false
	}
	return true
}

func ValidateCIDRv6(cidr string) error {
	ipa, _, err := cnet.ParseCIDROrIP(cidr)
	if err != nil {
		return err
	}
	if ipa.Version() == 6 {
		return nil
	}
	return fmt.Errorf("Invalid IPv6 CIDR: %s", cidr)
}

// validateCIDR validates the field is a valid (not strictly masked) IP network.
// An IP address is valid, and assumed to be fully masked (i.e /32 or /128)
func validateCIDR(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IP network: %s", n)
	_, _, err := cnet.ParseCIDROrIP(n)
	return err == nil
}

// validateCIDRs validates the field is a slice of valid (not strictly masked) IP networks.
// An IP address is valid, and assumed to be fully masked (i.e /32 or /128)
func validateCIDRs(fl validator.FieldLevel) bool {
	addrs := fl.Field().Interface().([]string)
	log.Debugf("Validate IP CIDRs: %s", addrs)
	for _, addr := range addrs {
		_, _, err := cnet.ParseCIDROrIP(addr)
		if err != nil {
			return false
		}
	}
	return true
}

func validateIPv4(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv4: %s", n)
	parsedIP := net.ParseIP(n)
	// Check if parsing was successful and if it is an IPv4 address.
	return parsedIP != nil && parsedIP.To4() != nil
}

func validateIPv6(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate IPv6: %s", n)
	parsedIP := net.ParseIP(n)
	// Check if parsing was successful and if it is NOT an IPv4 address.
	return parsedIP != nil && parsedIP.To4() == nil
}

// validateKeyValueList validates the field is a comma separated list of key=value pairs.
var kvRegex = regexp.MustCompile("^\\s*(\\w+)=(.*)$")

func validateKeyValueList(fl validator.FieldLevel) bool {
	n := fl.Field().String()
	log.Debugf("Validate KeyValueList: %s", n)

	if len(strings.TrimSpace(n)) == 0 {
		return true
	}

	for item := range strings.SplitSeq(n, ",") {
		if item == "" {
			// Accept empty items (e.g tailing ",")
			continue
		}
		kv := kvRegex.FindStringSubmatch(item)
		if kv == nil {
			return false
		}
	}

	return true
}

// validateIPPort validates the IP and Port given in either <IPv4>:<port> or [<IPv6>]:<port> or <IP> format
func validateIPPort(fl validator.FieldLevel) bool {
	ipPort := fl.Field().String()
	_, _, ok := processIPPort(ipPort)
	return ok
}

// processIPPort processes the IP and Port given in either <IPv4>:<port> or [<IPv6>]:<port> or <IP> format
// and return the IP, port and a bool if the format is as expected
func processIPPort(ipPort string) (string, int, bool) {
	if ipPort != "" {
		var ipStr, portStr string
		var err error
		var port uint64
		ipStr = ipPort
		// If PeerIP has both IP and port, validate both
		if IPv4PortFormat.MatchString(ipPort) || IPv6PortFormat.MatchString(ipPort) {
			ipStr, portStr, err = net.SplitHostPort(ipPort)
			if err != nil {
				log.Debugf("PeerIP value is invalid, it should either be \"<IP>\" or \"<IPv4>:<port>\" or \"[<IPv6>]:<port>\".")
				return "", 0, false
			}
			port, err = strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				log.Debugf("PeerIP value has invalid port.")
				return "", 0, false
			}
			if port < 1 {
				log.Debugf("PeerIP value has invalid port.")
				return "", 0, false
			}
		}

		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			log.Debugf("PeerIP value is invalid.")
			return "", 0, false
		}

		return ipStr, int(port), true
	}
	return "", 0, false
}

// validateHTTPMethods checks if the HTTP method match clauses are valid.
func validateHTTPMethods(methods []string) error {
	// check for duplicates
	s := set.FromArray(methods)
	if s.Len() != len(methods) {
		return fmt.Errorf("Invalid methods (duplicates): %v", methods)
	}
	return nil
}

// validateHTTPPaths checks if the HTTP path match clauses are valid.
func validateHTTPPaths(paths []api.HTTPPath) error {
	for _, path := range paths {
		if path.Exact != "" && path.Prefix != "" {
			return fmt.Errorf("Invalid path match. Both 'exact' and 'prefix' are set")
		}
		v := path.Exact
		if v == "" {
			v = path.Prefix
		}
		if v == "" {
			return fmt.Errorf("Invalid path match. Either 'exact' or 'prefix' must be set")
		}
		// Checks from https://tools.ietf.org/html/rfc3986#page-22
		if !strings.HasPrefix(v, "/") ||
			strings.ContainsAny(v, "? #") {
			return fmt.Errorf("Invalid path %s. (must start with `/` and not contain `?` or `#`", v)
		}
	}
	return nil
}

func validateHTTPRule(structLevel validator.StructLevel) {
	h := structLevel.Current().Interface().(api.HTTPMatch)
	log.Debugf("Validate HTTP Rule: %v", h)
	if err := validateHTTPMethods(h.Methods); err != nil {
		structLevel.ReportError(reflect.ValueOf(h.Methods), "Methods", "", reason(err.Error()), "")
	}
	if err := validateHTTPPaths(h.Paths); err != nil {
		structLevel.ReportError(reflect.ValueOf(h.Paths), "Paths", "", reason(err.Error()), "")
	}
}

func validatePort(structLevel validator.StructLevel) {
	p := structLevel.Current().Interface().(numorstring.Port)

	// Check that the port range is in the correct order.  The YAML parsing also checks this,
	// but this protects against misuse of the programmatic API.
	log.Debugf("Validate port: %v", p)
	if p.MinPort > p.MaxPort {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid"), "")
	}

	if p.PortName != "" {
		if p.MinPort != 0 || p.MaxPort != 0 {
			structLevel.ReportError(reflect.ValueOf(p.PortName),
				"Port", "", reason("named port invalid, if name is specified, min and max should be 0"), "")
		}
	} else if p.MinPort < 1 {
		structLevel.ReportError(reflect.ValueOf(p.MinPort),
			"Port", "", reason("port range invalid, port number must be between 1 and 65535"), "")
	} else if p.MaxPort < 1 {
		structLevel.ReportError(reflect.ValueOf(p.MaxPort),
			"Port", "", reason("port range invalid, port number must be between 1 and 65535"), "")
	}
}

func validateIPNAT(structLevel validator.StructLevel) {
	i := structLevel.Current().Interface().(internalapi.IPNAT)
	log.Debugf("Internal IP: %s; External IP: %s", i.InternalIP, i.ExternalIP)

	iip, _, err := cnet.ParseCIDROrIP(i.InternalIP)
	if err != nil {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP),
			"InternalIP", "", reason("invalid IP address"), "")
	}

	eip, _, err := cnet.ParseCIDROrIP(i.ExternalIP)
	if err != nil {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP),
			"InternalIP", "", reason("invalid IP address"), "")
	}

	// An IPNAT must have both the internal and external IP versions the same.
	if iip.Version() != eip.Version() {
		structLevel.ReportError(reflect.ValueOf(i.ExternalIP),
			"ExternalIP", "", reason("mismatched IP versions"), "")
	}
}

func validateFelixConfigSpec(structLevel validator.StructLevel) {
	c := structLevel.Current().Interface().(api.FelixConfigurationSpec)

	// Validate that the node port ranges list contains only numeric ports.
	// Max length (7) is enforced by CRD MaxItems.
	if c.KubeNodePortRanges != nil {
		for _, p := range *c.KubeNodePortRanges {
			if p.PortName != "" {
				structLevel.ReportError(reflect.ValueOf(*c.KubeNodePortRanges),
					"KubeNodePortRanges", "",
					reason("node port ranges should not contain named ports"), "")
			}
		}
	}

	// Validate that the externalNodesCIDRList is composed of valid cidr's.
	if c.ExternalNodesCIDRList != nil {
		for _, cidr := range *c.ExternalNodesCIDRList {
			log.Debugf("Cidr is: %s", cidr)
			ip, _, err := cnet.ParseCIDROrIP(cidr)
			if err != nil {
				structLevel.ReportError(reflect.ValueOf(cidr),
					"ExternalNodesCIDRList", "", reason("has invalid CIDR(s)"), "")
			} else if ip.Version() != 4 {
				structLevel.ReportError(reflect.ValueOf(cidr),
					"ExternalNodesCIDRList", "", reason("has invalid IPv6 CIDR"), "")
			}
		}
	}

	// Validate that the OpenStack region is suitable for use in a namespace name.
	const regionNamespacePrefix = "openstack-region-"
	const maxRegionLength int = k8svalidation.DNS1123LabelMaxLength - len(regionNamespacePrefix)
	if len(c.OpenstackRegion) > maxRegionLength {
		structLevel.ReportError(reflect.ValueOf(c.OpenstackRegion),
			"OpenstackRegion", "", reason("is too long"), "")
	} else if len(c.OpenstackRegion) > 0 {
		problems := k8svalidation.IsDNS1123Label(c.OpenstackRegion)
		if len(problems) > 0 {
			structLevel.ReportError(reflect.ValueOf(c.OpenstackRegion),
				"OpenstackRegion", "", reason("must be a valid DNS label"), "")
		}
	}

	if c.NATOutgoingAddress != "" {
		parsedAddress := cnet.ParseIP(c.NATOutgoingAddress)
		if parsedAddress == nil || parsedAddress.Version() != 4 {
			structLevel.ReportError(reflect.ValueOf(c.NATOutgoingAddress),
				"NATOutgoingAddress", "", reason("is not a valid IPv4 address"), "")
		}
	}

	if c.DeviceRouteSourceAddress != "" {
		parsedAddress := cnet.ParseIP(c.DeviceRouteSourceAddress)
		if parsedAddress == nil || parsedAddress.Version() != 4 {
			structLevel.ReportError(reflect.ValueOf(c.DeviceRouteSourceAddress),
				"DeviceRouteSourceAddress", "", reason("is not a valid IPv4 address"), "")
		}
	}

	if c.DeviceRouteSourceAddressIPv6 != "" {
		parsedAddress := cnet.ParseIP(c.DeviceRouteSourceAddressIPv6)
		if parsedAddress == nil || parsedAddress.Version() != 6 {
			structLevel.ReportError(reflect.ValueOf(c.DeviceRouteSourceAddressIPv6),
				"DeviceRouteSourceAddressIPv6", "", reason("is not a valid IPv6 address"), "")
		}
	}

	if c.RouteTableRanges != nil && c.RouteTableRanges.NumDesignatedTables() > int(routeTableRangeMaxTables) {
		structLevel.ReportError(reflect.ValueOf(c.RouteTableRanges),
			"RouteTableRanges", "", reason("targets too many tables"), "")
	}
}

func validateWorkloadEndpointSpec(structLevel validator.StructLevel) {
	w := structLevel.Current().Interface().(internalapi.WorkloadEndpointSpec)

	// The configured networks only support /32 (for IPv4) and /128 (for IPv6) at present.
	for _, netw := range w.IPNetworks {
		_, nw, err := cnet.ParseCIDROrIP(netw)
		if err != nil {
			structLevel.ReportError(reflect.ValueOf(netw),
				"IPNetworks", "", reason("invalid CIDR"), "")
		}

		ones, bits := nw.Mask.Size()
		if bits != ones {
			structLevel.ReportError(reflect.ValueOf(w.IPNetworks),
				"IPNetworks", "", reason("IP network contains multiple addresses"), "")
		}
	}

	_, v4gw, err := cnet.ParseCIDROrIP(w.IPv4Gateway)
	if err != nil {
		structLevel.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid CIDR"), "")
	}

	_, v6gw, err := cnet.ParseCIDROrIP(w.IPv6Gateway)
	if err != nil {
		structLevel.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid CIDR"), "")
	}

	if v4gw.IP != nil && v4gw.Version() != 4 {
		structLevel.ReportError(reflect.ValueOf(w.IPv4Gateway),
			"IPv4Gateway", "", reason("invalid IPv4 gateway address specified"), "")
	}

	if v6gw.IP != nil && v6gw.Version() != 6 {
		structLevel.ReportError(reflect.ValueOf(w.IPv6Gateway),
			"IPv6Gateway", "", reason("invalid IPv6 gateway address specified"), "")
	}

	// If NATs have been specified, then they should each be within the configured networks of
	// the endpoint.
	if len(w.IPNATs) > 0 {
		valid := false
		for _, nat := range w.IPNATs {
			_, natCidr, err := cnet.ParseCIDROrIP(nat.InternalIP)
			if err != nil {
				structLevel.ReportError(reflect.ValueOf(nat.InternalIP),
					"IPNATs", "", reason("invalid InternalIP CIDR"), "")
			}
			// Check each NAT to ensure it is within the configured networks.  If any
			// are not then exit without further checks.
			valid = false
			for _, cidr := range w.IPNetworks {
				_, nw, err := cnet.ParseCIDROrIP(cidr)
				if err != nil {
					structLevel.ReportError(reflect.ValueOf(cidr),
						"IPNetworks", "", reason("invalid CIDR"), "")
				}

				if nw.Contains(natCidr.IP) {
					valid = true
					break
				}
			}
			if !valid {
				break
			}
		}

		if !valid {
			structLevel.ReportError(reflect.ValueOf(w.IPNATs),
				"IPNATs", "", reason("NAT is not in the endpoint networks"), "")
		}
	}
}

func validateIPPoolSpec(structLevel validator.StructLevel) {
	pool := structLevel.Current().Interface().(api.IPPoolSpec)

	// Spec.CIDR field must not be empty.
	if pool.CIDR == "" {
		structLevel.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason("IPPool CIDR must be specified"), "")
	}

	// Make sure the CIDR is parsable.
	ipAddr, cidr, err := cnet.ParseCIDROrIP(pool.CIDR)
	if err != nil {
		structLevel.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason("IPPool CIDR must be a valid subnet"), "")
		return
	}

	// Normalize the CIDR before persisting.
	pool.CIDR = cidr.String()

	// Default the blockSize
	if pool.BlockSize == 0 {
		if ipAddr.Version() == 4 {
			pool.BlockSize = 26
		} else {
			pool.BlockSize = 122
		}
	}

	// The Calico IPAM places restrictions on the minimum IP pool size.  If
	// the ippool is enabled, check that the pool is at least the minimum size.
	if !pool.Disabled {
		ones, _ := cidr.Mask.Size()
		log.Debugf("Pool CIDR: %s, mask: %d, blockSize: %d", cidr.String(), ones, pool.BlockSize)
		if ones > pool.BlockSize {
			structLevel.ReportError(reflect.ValueOf(pool.CIDR),
				"IPpool.CIDR", "", reason("IP pool size is too small for use with Calico IPAM. It must be equal to or greater than the block size."), "")
		}
	}

	// The Calico CIDR should be strictly masked
	log.Debugf("IPPool CIDR: %s, Masked IP: %d", pool.CIDR, cidr.IP)
	if cidr.IP.String() != ipAddr.String() {
		structLevel.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(poolUnstictCIDR), "")
	}

	// IPv4 link local subnet.
	ipv4LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
	// IPv6 link local subnet.
	ipv6LinkLocalNet := net.IPNet{
		IP:   net.ParseIP("fe80::"),
		Mask: net.CIDRMask(10, 128),
	}

	// IP Pool CIDR cannot overlap with IPv4 or IPv6 link local address range.
	if cidr.Version() == 4 && cidr.IsNetOverlap(ipv4LinkLocalNet) {
		structLevel.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(overlapsV4LinkLocal), "")
	}

	if cidr.Version() == 6 && cidr.IsNetOverlap(ipv6LinkLocalNet) {
		structLevel.ReportError(reflect.ValueOf(pool.CIDR),
			"IPpool.CIDR", "", reason(overlapsV6LinkLocal), "")
	}

	// AllowedUses enum, LB constraints, Tunnel/namespaceSelector, and global() selector
	// checks are handled by CEL XValidation rules and CRD schema Enum on the IPPoolAllowedUse type.
}

func validateRule(structLevel validator.StructLevel) {
	rule := structLevel.Current().Interface().(api.Rule)

	// If the protocol does not support ports check that the port values have not
	// been specified.
	if rule.Protocol == nil {
		if !numorstring.AllPortsAreNamed(rule.Source.Ports) {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Ports),
				"Source.Ports", "", reason(protocolSingleOrRangePortsMsg), "")
		}
		if !numorstring.AllPortsAreNamed(rule.Source.NotPorts) {
			structLevel.ReportError(reflect.ValueOf(rule.Source.NotPorts),
				"Source.NotPorts", "", reason(protocolSingleOrRangePortsMsg), "")
		}
		if !numorstring.AllPortsAreNamed(rule.Destination.Ports) {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.Ports),
				"Destination.Ports", "", reason(protocolSingleOrRangePortsMsg), "")
		}
		if !numorstring.AllPortsAreNamed(rule.Destination.NotPorts) {
			structLevel.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
				"Destination.NotPorts", "", reason(protocolSingleOrRangePortsMsg), "")
		}
	} else { // Protocol != nil
		if !rule.Protocol.SupportsPorts() {
			if len(rule.Source.Ports) > 0 {
				structLevel.ReportError(reflect.ValueOf(rule.Source.Ports),
					"Source.Ports", "", reason(protocolPortsMsg), "")
			}
			if len(rule.Source.NotPorts) > 0 {
				structLevel.ReportError(reflect.ValueOf(rule.Source.NotPorts),
					"Source.NotPorts", "", reason(protocolPortsMsg), "")
			}

			if len(rule.Destination.Ports) > 0 {
				structLevel.ReportError(reflect.ValueOf(rule.Destination.Ports),
					"Destination.Ports", "", reason(protocolPortsMsg), "")
			}
			if len(rule.Destination.NotPorts) > 0 {
				structLevel.ReportError(reflect.ValueOf(rule.Destination.NotPorts),
					"Destination.NotPorts", "", reason(protocolPortsMsg), "")
			}
		}
	}

	var seenV4, seenV6 bool

	scanNets := func(nets []string, fieldName string) {
		var v4, v6 bool
		isNegatedField := fieldName == "Source.NotNets" || fieldName == "Destination.NotNets"
		for _, n := range nets {
			_, cidr, err := cnet.ParseCIDR(n)
			if err != nil {
				structLevel.ReportError(reflect.ValueOf(n), fieldName,
					"", reason("invalid CIDR"), "")
			} else {
				v4 = v4 || cidr.Version() == 4
				v6 = v6 || cidr.Version() == 6

				// Check for catch-all CIDR in negated context, which creates logical contradictions
				if isNegatedField {
					if (cidr.Version() == 4 && n == "0.0.0.0/0") ||
						(cidr.Version() == 6 && cidr.Mask.String() == cnet.MustParseCIDR("::/0").Mask.String() &&
							cidr.IP.Equal(cnet.MustParseCIDR("::/0").IP)) {
						structLevel.ReportError(reflect.ValueOf(n), fieldName,
							"", reason("catch-all CIDR in negation creates logical contradiction (matches no traffic)"), "")
					}
				}
			}
		}
		if rule.IPVersion != nil && ((v4 && *rule.IPVersion != 4) || (v6 && *rule.IPVersion != 6)) {
			structLevel.ReportError(reflect.ValueOf(rule.Source.Nets), fieldName,
				"", reason("rule IP version doesn't match CIDR version"), "")
		}
		if v4 && seenV6 || v6 && seenV4 || v4 && v6 {
			// This field makes the rule inconsistent.
			structLevel.ReportError(reflect.ValueOf(nets), fieldName,
				"", reason("rule contains both IPv4 and IPv6 CIDRs"), "")
		}
		seenV4 = seenV4 || v4
		seenV6 = seenV6 || v6
	}

	scanNets(rule.Source.Nets, "Source.Nets")
	scanNets(rule.Source.NotNets, "Source.NotNets")
	scanNets(rule.Destination.Nets, "Destination.Nets")
	scanNets(rule.Destination.NotNets, "Destination.NotNets")

}

func validateEntityRule(structLevel validator.StructLevel) {
	rule := structLevel.Current().Interface().(api.EntityRule)

	// The selector global() check, services+selector/notSelector, and services+nets/notNets
	// checks exceed the CEL cost budget (EntityRule is nested inside Rule arrays without
	// MaxItems), so they remain in Go.
	if strings.Contains(rule.Selector, "global(") {
		structLevel.ReportError(reflect.ValueOf(rule.Selector),
			"Selector field", "", reason("global() can only be used in an EntityRule namespaceSelector"), "")
	}

	if rule.Services != nil {
		if rule.Services.Name == "" {
			structLevel.ReportError(reflect.ValueOf(rule.Services),
				"Services field", "", reason("must specify a service name"), "")
		}
		if rule.Selector != "" || rule.NotSelector != "" {
			structLevel.ReportError(reflect.ValueOf(rule.Services),
				"Services field", "", reason("cannot specify Selector/NotSelector and Services on the same rule"), "")
		}
		if len(rule.Nets) != 0 || len(rule.NotNets) != 0 {
			structLevel.ReportError(reflect.ValueOf(rule.Services),
				"Services field", "", reason("cannot specify Nets/NotNets and Services on the same rule"), "")
		}
	}

	if strings.Contains(rule.NamespaceSelector, "global(") &&
		rule.NamespaceSelector != "global()" {
		// Looks like the selector has a global() clause but it's not _only_
		// that.  Tokenize the selector so we can more easily check it.
		var tokenArr [16]tokenizer.Token
		tokens, err := tokenizer.AppendTokens(tokenArr[:0], rule.NamespaceSelector)
		if err != nil || len(tokens) > 2 || tokens[0].Kind != tokenizer.TokGlobal {
			// If the namespaceSelector contains global(), then it should be the only selector.
			structLevel.ReportError(reflect.ValueOf(rule.NamespaceSelector),
				"NamespaceSelector field", "", reason(globalSelectorOnly), "")
		}
	}
}

func validateIPAMConfigSpec(structLevel validator.StructLevel) {
	ics := structLevel.Current().Interface().(api.IPAMConfigurationSpec)

	if ics.MaxBlocksPerHost < 0 {
		structLevel.ReportError(reflect.ValueOf(ics.MaxBlocksPerHost), "MaxBlocksPerHost", "",
			reason("must be greater than or equal to 0"), "")
	}
}

func validateNodeSpec(structLevel validator.StructLevel) {
	ns := structLevel.Current().Interface().(internalapi.NodeSpec)

	if ns.BGP != nil {
		if reflect.DeepEqual(*ns.BGP, internalapi.NodeBGPSpec{}) {
			structLevel.ReportError(reflect.ValueOf(ns.BGP), "BGP", "",
				reason("Spec.BGP should not be empty"), "")
		}
	}
}

func validateBGPPeerSpec(structLevel validator.StructLevel) {
	ps := structLevel.Current().Interface().(api.BGPPeerSpec)

	// Validate that reachableBy and peerIP are the same address family. The basic
	// "reachableBy requires peerIP" and "keepOriginalNextHop vs nextHopMode" checks
	// are handled by CEL XValidation rules on the CRD.
	if ps.ReachableBy != "" && ps.PeerIP != "" {
		reachableByAddr := cnet.ParseIP(ps.ReachableBy)
		if reachableByAddr == nil {
			structLevel.ReportError(reflect.ValueOf(ps.ReachableBy), "ReachableBy", "",
				reason("ReachableBy is invalid address"), "")
			return
		}
		peerAddrStr, _, ok := processIPPort(ps.PeerIP)
		if !ok {
			structLevel.ReportError(reflect.ValueOf(ps.PeerIP), "PeerIP", "",
				reason("PeerIP is invalid address"), "")
			return
		}
		peerAddr := cnet.ParseIP(peerAddrStr)
		if peerAddr == nil {
			structLevel.ReportError(reflect.ValueOf(ps.PeerIP), "PeerIP", "",
				reason("PeerIP is invalid IP address"), "")
			return
		}
		if reachableByAddr.Version() != peerAddr.Version() {
			structLevel.ReportError(reflect.ValueOf(ps.ReachableBy), "ReachableBy", "",
				reason("ReachableBy and PeerIP address family mismatched"), "")
		}
	}
}

// validateReachableByField validates that reachableBy value, the address of the
// gateway the BGP peer is connected to, is a correct address
func validateReachableByField(fl validator.FieldLevel) bool {
	reachableBy := fl.Field().String()

	if reachableBy != "" {
		reachableByAddr := cnet.ParseIP(reachableBy)
		if reachableByAddr == nil {
			log.Debugf("ReachableBy value is invalid address")
			return false
		}
	}
	return true
}

func validateEndpointPort(structLevel validator.StructLevel) {
	port := structLevel.Current().Interface().(api.EndpointPort)

	if !port.Protocol.SupportsPorts() {
		structLevel.ReportError(
			reflect.ValueOf(port.Protocol),
			"EndpointPort.Protocol",
			"",
			reason("EndpointPort protocol does not support ports."),
			"",
		)
	}
}

func validateWorkloadEndpointPort(structLevel validator.StructLevel) {
	port := structLevel.Current().Interface().(internalapi.WorkloadEndpointPort)

	if !port.Protocol.SupportsPorts() {
		structLevel.ReportError(
			reflect.ValueOf(port.Protocol),
			"WorkloadEndpointPort.Protocol",
			"",
			reason("WorkloadEndpointPort protocol does not support ports."),
			"",
		)
	}

	if port.Name == "" && port.HostPort == 0 {
		structLevel.ReportError(
			reflect.ValueOf(port.Name),
			"WorkloadEndpointPort.Name",
			"",
			reason("WorkloadEndpointPort name must not be empty if no HostPort is specified"),
			"",
		)
	}
}

func validateProtoPort(structLevel validator.StructLevel) {
	m := structLevel.Current().Interface().(api.ProtoPort)

	if m.Protocol != "TCP" && m.Protocol != "UDP" && m.Protocol != "SCTP" {
		structLevel.ReportError(
			reflect.ValueOf(m.Protocol),
			"ProtoPort.Protocol",
			"",
			reason("protocol must be 'TCP' or 'UDP' or 'SCTP'."),
			"",
		)
	}
}

func validateObjectMeta(structLevel validator.StructLevel) {
	om := structLevel.Current().Interface().(metav1.ObjectMeta)

	// Check the name is within the max length.
	if len(om.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(om.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(om.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	// Uses the k8s DN1123 subdomain format for most resource names.
	matched := nameRegex.MatchString(om.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(om.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters, '-' or '.' (regex: "+nameSubdomainFmt+")"),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, om.Annotations)
	validateObjectMetaLabels(structLevel, om.Labels)
}

func validateTier(structLevel validator.StructLevel) {
	tier := structLevel.Current().Interface().(api.Tier)

	// Check the name is within the max length.
	// Tier names are dependent on the label max length since policy lookup by tier in KDD requires the name to fit in a label.
	if len(tier.Name) > k8svalidation.DNS1123LabelMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(tier.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(tier.Name)-k8svalidation.DNS1123LabelMaxLength)),
			"",
		)
	}

	// Tiers must have simple (no dot) names, since they appear as sub-components of other names.
	matched := tierNameRegex.MatchString(tier.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(tier.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
			"",
		)
	}

	// Well-known tier order enforcement is handled by CEL XValidation rules on the CRD.

	validateObjectMetaAnnotations(structLevel, tier.Annotations)
	validateObjectMetaLabels(structLevel, tier.Labels)
}

func validateNetworkPolicySpec(spec *api.NetworkPolicySpec, structLevel validator.StructLevel) {
	// Types uniqueness is enforced by +listType=set on the CRD.

	for _, r := range spec.Egress {
		// Services are only allowed in the destination on Egress rules.
		if r.Source.Services != nil {
			structLevel.ReportError(
				reflect.ValueOf(r.Source.Services), "Services", "",
				reason("not allowed in egress rule source"), "",
			)
		}

		// Check (and disallow) rules with application layer policy for egress rules.
		useALP, v, f := ruleUsesAppLayerPolicy(&r)
		if useALP {
			structLevel.ReportError(v, f, "", reason("not allowed in egress rule"), "")
		}
	}

	// Services are only allowed in the source on Ingress rules.
	for _, r := range spec.Ingress {
		if r.Destination.Services != nil {
			structLevel.ReportError(
				reflect.ValueOf(r.Destination.Services), "Services", "",
				reason("not allowed in ingress rule destination"), "",
			)
		}
	}

	// global() selector checks on Selector and ServiceAccountSelector are handled
	// by CEL XValidation rules on the CRD.
}

func validateNetworkPolicy(structLevel validator.StructLevel) {
	np := structLevel.Current().Interface().(api.NetworkPolicy)
	spec := np.Spec

	// Check the name is within the max length.
	if len(np.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(np.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(np.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	// Uses the k8s DN1123 label format for policy names (plus knp.default prefixed k8s policies).
	matched := networkPolicyNameRegex.MatchString(np.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(np.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, np.Annotations)
	validateObjectMetaLabels(structLevel, np.Labels)

	validateNetworkPolicySpec(&spec, structLevel)
}

func validateStagedNetworkPolicy(structLevel validator.StructLevel) {
	staged := structLevel.Current().Interface().(api.StagedNetworkPolicy)

	// Check the name is within the max length.
	if len(staged.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(staged.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(staged.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	// Uses the k8s DN1123 label format for policy names (plus knp.default prefixed k8s policies).
	matched := networkPolicyNameRegex.MatchString(staged.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(staged.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, staged.Annotations)
	validateObjectMetaLabels(structLevel, staged.Labels)

	_, enforced := api.ConvertStagedPolicyToEnforced(&staged)

	if staged.Spec.StagedAction == api.StagedActionDelete {
		empty := api.NetworkPolicySpec{}
		empty.Tier = enforced.Spec.Tier
		if !reflect.DeepEqual(empty, enforced.Spec) {
			structLevel.ReportError(reflect.ValueOf(staged.Spec),
				"StagedNetworkPolicySpec", "", reason("Spec fields, except Tier, should all be zero-value if stagedAction is Delete"), "")
		}
	} else {
		validateNetworkPolicySpec(&enforced.Spec, structLevel)
	}
}

func validateNetworkSet(structLevel validator.StructLevel) {
	ns := structLevel.Current().Interface().(api.NetworkSet)
	for k := range ns.GetLabels() {
		if k == "projectcalico.org/namespace" {
			// The namespace label should only be used when mapping the real namespace through
			// to the v1 datamodel.  It shouldn't appear in the v3 datamodel.
			structLevel.ReportError(
				reflect.ValueOf(k),
				"Metadata.Labels (label)",
				"",
				reason("projectcalico.org/namespace is not a valid label name"),
				"",
			)
		}
	}
}

func validateGlobalNetworkSet(structLevel validator.StructLevel) {
	gns := structLevel.Current().Interface().(api.GlobalNetworkSet)
	for k := range gns.GetLabels() {
		if k == "projectcalico.org/namespace" {
			// The namespace label should only be used when mapping the real namespace through
			// to the v1 datamodel.  It shouldn't appear in the v3 datamodel.
			structLevel.ReportError(
				reflect.ValueOf(k),
				"Metadata.Labels (label)",
				"",
				reason("projectcalico.org/namespace is not a valid label name"),
				"",
			)
		}
	}
}

func validateGlobalNetworkPolicySpec(spec *api.GlobalNetworkPolicySpec, structLevel validator.StructLevel) {
	// Types uniqueness is enforced by +listType=set on the CRD.

	for _, r := range spec.Egress {
		// Services are only allowed as a destination on Egress rules.
		if r.Source.Services != nil {
			structLevel.ReportError(
				reflect.ValueOf(r.Source.Services), "Services", "",
				reason("not allowed in egress rule source"), "",
			)
		}

		// Check (and disallow) rules with application layer policy for egress rules.
		useALP, v, f := ruleUsesAppLayerPolicy(&r)
		if useALP {
			structLevel.ReportError(v, f, "", reason("not allowed in egress rules"), "")
		}
	}

	// Services are only allowed as a source on Ingress rules.
	for _, r := range spec.Ingress {
		if r.Destination.Services != nil {
			structLevel.ReportError(
				reflect.ValueOf(r.Destination.Services), "Services", "",
				reason("not allowed in ingress rule destination"), "",
			)
		}
	}

	// If a ServiceSelector is specified by name, we also need a namespace. At a global scope,
	// service names are not fully qualified and so need a namespace.
	for _, r := range spec.Egress {
		if r.Destination.Services != nil && r.Destination.Services.Namespace == "" {
			structLevel.ReportError(
				reflect.ValueOf(r.Destination.Services.Namespace), "Namespace", "",
				reason("must specify a namespace"), "",
			)
		}
	}
	for _, r := range spec.Ingress {
		if r.Source.Services != nil && r.Source.Services.Namespace == "" {
			structLevel.ReportError(
				reflect.ValueOf(r.Source.Services.Namespace), "Namespace", "",
				reason("must specify a namespace"), "",
			)
		}
	}

	// global() selector checks on Selector, ServiceAccountSelector, and NamespaceSelector
	// are handled by CEL XValidation rules on the CRD.
}

func validateGlobalNetworkPolicy(structLevel validator.StructLevel) {
	gnp := structLevel.Current().Interface().(api.GlobalNetworkPolicy)
	spec := gnp.Spec

	// Check the name is within the max length.
	if len(gnp.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(gnp.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(gnp.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	// Uses the k8s DN1123 label format for policy names.
	matched := globalNetworkPolicyNameRegex.MatchString(gnp.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(gnp.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, gnp.Annotations)
	validateObjectMetaLabels(structLevel, gnp.Labels)
	validateGlobalNetworkPolicySpec(&spec, structLevel)
}

func validateStagedGlobalNetworkPolicy(structLevel validator.StructLevel) {
	staged := structLevel.Current().Interface().(api.StagedGlobalNetworkPolicy)

	// Check the name is within the max length.
	if len(staged.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(staged.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(staged.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	// Uses the k8s DN1123 label format for policy names.
	matched := globalNetworkPolicyNameRegex.MatchString(staged.Name)
	if !matched {
		structLevel.ReportError(
			reflect.ValueOf(staged.Name),
			"Metadata.Name",
			"",
			reason("name must consist of lower case alphanumeric characters or '-' (regex: "+nameLabelFmt+")"),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, staged.Annotations)
	validateObjectMetaLabels(structLevel, staged.Labels)

	_, enforced := api.ConvertStagedGlobalPolicyToEnforced(&staged)

	if staged.Spec.StagedAction == api.StagedActionDelete {
		// the network policy fields should all "zero-value" when the update type is "delete"
		empty := api.GlobalNetworkPolicySpec{}
		empty.Tier = enforced.Spec.Tier
		if !reflect.DeepEqual(empty, enforced.Spec) {
			structLevel.ReportError(reflect.ValueOf(staged.Spec),
				"StagedGlobalNetworkPolicySpec", "", reason("Spec fields, except Tier, should all be zero-value if stagedAction is Delete"), "")
		}
	} else {
		validateGlobalNetworkPolicySpec(&enforced.Spec, structLevel)
	}
}

func validateStagedKubernetesNetworkPolicy(structLevel validator.StructLevel) {
	staged := structLevel.Current().Interface().(api.StagedKubernetesNetworkPolicy)

	// Check the name is within the max length.
	if len(staged.Name) > k8svalidation.DNS1123SubdomainMaxLength {
		structLevel.ReportError(
			reflect.ValueOf(staged.Name),
			"Metadata.Name",
			"",
			reason(fmt.Sprintf("name is too long by %d bytes", len(staged.Name)-k8svalidation.DNS1123SubdomainMaxLength)),
			"",
		)
	}

	validateObjectMetaAnnotations(structLevel, staged.Annotations)
	validateObjectMetaLabels(structLevel, staged.Labels)

	if staged.Spec.StagedAction == api.StagedActionDelete {
		// the network policy fields should all "zero-value" when the update type is "delete"
		empty := api.NewStagedKubernetesNetworkPolicy()
		empty.Spec.StagedAction = api.StagedActionDelete
		if !reflect.DeepEqual(empty.Spec, staged.Spec) {
			structLevel.ReportError(reflect.ValueOf(staged.Spec),
				"StagedKubernetesNetworkPolicySpec", "", reason("Spec fields should all be zero-value if stagedAction is Delete"), "")
		}
	} else {
		c := calicoconversion.NewConverter()
		_, v1np := api.ConvertStagedKubernetesPolicyToK8SEnforced(&staged)
		npKVPair, err := c.K8sNetworkPolicyToCalico(v1np)
		if err != nil {
			structLevel.ReportError(
				reflect.ValueOf(staged.Spec),
				"PolicySpec",
				"",
				reason(fmt.Sprintf("conversion to stagednetworkpolicy failed %v", err)),
				"",
			)
		}

		v3np := npKVPair.Value.(*api.NetworkPolicy)
		validateNetworkPolicySpec(&v3np.Spec, structLevel)
	}
}

func validateObjectMetaAnnotations(structLevel validator.StructLevel, annotations map[string]string) {
	var totalSize int64
	for k, v := range annotations {
		for _, errStr := range k8svalidation.IsQualifiedName(strings.ToLower(k)) {
			structLevel.ReportError(
				reflect.ValueOf(k),
				"Metadata.Annotations (key)",
				"",
				reason(errStr),
				"",
			)
		}
		totalSize += (int64)(len(k)) + (int64)(len(v))
	}

	if totalSize > (int64)(totalAnnotationSizeLimitB) {
		structLevel.ReportError(
			reflect.ValueOf(annotations),
			"Metadata.Annotations (key)",
			"",
			reason(fmt.Sprintf("total size of annotations is too large by %d bytes", totalSize-totalAnnotationSizeLimitB)),
			"",
		)
	}
}

func validateObjectMetaLabels(structLevel validator.StructLevel, labels map[string]string) {
	for k, v := range labels {
		for _, errStr := range k8svalidation.IsQualifiedName(k) {
			structLevel.ReportError(
				reflect.ValueOf(k),
				"Metadata.Labels (label)",
				"",
				reason(errStr),
				"",
			)
		}
		for _, errStr := range k8svalidation.IsValidLabelValue(v) {
			structLevel.ReportError(
				reflect.ValueOf(v),
				"Metadata.Labels (value)",
				"",
				reason(errStr),
				"",
			)
		}
	}
}

func validateRuleMetadata(structLevel validator.StructLevel) {
	ruleMeta := structLevel.Current().Interface().(api.RuleMetadata)
	validateObjectMetaAnnotations(structLevel, ruleMeta.Annotations)
}

func validateBGPConfigurationSpec(structLevel validator.StructLevel) {
	spec := structLevel.Current().Interface().(api.BGPConfigurationSpec)

	// check if Spec.Communities[] are valid
	communities := spec.Communities
	for _, community := range communities {
		isValid := isValidCommunity(community.Value, "Spec.Communities[].Value", structLevel)
		if !isValid {
			log.Warningf("community value is invalid: %v", community.Value)
			structLevel.ReportError(reflect.ValueOf(community.Value), "Spec.Communities[].Value", "",
				reason("invalid community value or format used."), "")
		}
	}

	if (len(spec.PrefixAdvertisements) == 0) && (len(communities) != 0) {
		structLevel.ReportError(reflect.ValueOf(communities), "Spec.Communities[]", "",
			reason("communities are defined but not used in Spec.PrefixAdvertisement[]."), "")
	}

	// check if Spec.PrefixAdvertisement.Communities are valid
	for _, pa := range spec.PrefixAdvertisements {
		_, _, err := cnet.ParseCIDROrIP(pa.CIDR)
		if err != nil {
			log.Warningf("CIDR value is invalid: %v", pa.CIDR)
			structLevel.ReportError(reflect.ValueOf(pa.CIDR), "Spec.PrefixAdvertisement[].CIDR", "",
				reason("invalid CIDR value."), "")
		}

		for _, v := range pa.Communities {
			isValid := isValidCommunity(v, "Spec.PrefixAdvertisement[].Communities[]", structLevel)
			if !isValid {
				if !isCommunityDefined(v, communities) {
					structLevel.ReportError(reflect.ValueOf(v), "Spec.PrefixAdvertisement[].Communities[]", "",
						reason("community used is invalid or not defined."), "")
				}
			}
		}
	}

}

func validateBlockAffinitySpec(structLevel validator.StructLevel) {
	spec := structLevel.Current().Interface().(api.BlockAffinitySpec)
	if spec.Deleted {
		structLevel.ReportError(reflect.ValueOf(spec), "Spec.Deleted", "", reason("spec.Deleted cannot be set to \"true\""), "")
	}
}

var htoNameRegex = regexp.MustCompile("^[a-zA-Z0-9_ -]+$")

func validateHealthTimeoutOverride(structLevel validator.StructLevel) {
	hto := structLevel.Current().Interface().(api.HealthTimeoutOverride)
	if !htoNameRegex.MatchString(hto.Name) {
		structLevel.ReportError(reflect.ValueOf(hto), "HealthTimeoutOverride.Name", "", reason("name should match regex "+htoNameRegex.String()), "")
	}
	if hto.Timeout.Duration < 0 {
		structLevel.ReportError(reflect.ValueOf(hto), "HealthTimeoutOverride.Timeout", "", reason("Timeout should not be negative"), "")
	}
}

func isCommunityDefined(community string, communityKVPairs []api.Community) bool {
	for _, val := range communityKVPairs {
		if val.Name == community {
			return true
		}
	}
	return false
}

func isValidCommunity(communityValue string, fieldName string, structLevel validator.StructLevel) bool {
	if standardCommunity.MatchString(communityValue) {
		validateCommunityValue(communityValue, fieldName, structLevel, false)
	} else if largeCommunity.MatchString(communityValue) {
		validateCommunityValue(communityValue, fieldName, structLevel, true)
	} else {
		return false
	}
	return true
}

// Validate that if standard community is used, community value must follow `aa:nn` format, where `aa` and `nn` are 16 bit integers,
// and if large community is used, value must follow `aa:nn:mm` format, where all `aa`, `nn` and `mm` are 32 bit integers.
func validateCommunityValue(val string, fieldName string, structLevel validator.StructLevel, isLargeCommunity bool) {
	splitValue := number.FindAllString(val, -1)
	bitSize := 16

	if isLargeCommunity {
		bitSize = 32
	}

	for _, v := range splitValue {
		_, err := strconv.ParseUint(v, 10, bitSize)
		if err != nil {
			structLevel.ReportError(reflect.ValueOf(val), fieldName, "",
				reason(fmt.Sprintf("invalid community value, expected %d bit value", bitSize)), "")
		}
	}
}

// ruleUsesAppLayerPolicy checks if a rule uses application layer policy, and
// if it does, returns true and the type of application layer clause. If it does
// not it returns false and the empty string.
func ruleUsesAppLayerPolicy(rule *api.Rule) (bool, reflect.Value, string) {
	if rule.HTTP != nil {
		return true, reflect.ValueOf(rule.HTTP), "HTTP"
	}
	return false, reflect.Value{}, ""
}
