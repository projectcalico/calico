// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kardianos/osext"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/stringutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
)

const (
	MinIptablesMarkBits = 2
)

type Metadata struct {
	Name              string
	Type              string
	DefaultString     string
	Default           interface{}
	ZeroValue         interface{}
	NonZero           bool
	DieOnParseFailure bool
	Local             bool
}

func (m *Metadata) GetMetadata() *Metadata {
	return m
}

func (m *Metadata) parseFailed(raw, msg string) error {
	return fmt.Errorf("failed to parse config parameter %v; value %#v: %v", m.Name, raw, msg)
}

func (m *Metadata) setDefault(config *Config) {
	log.Debugf("Defaulting: %v to %v", m.Name, m.Default)
	field := reflect.ValueOf(config).Elem().FieldByName(m.Name)
	value := reflect.ValueOf(m.Default)
	field.Set(value)
}

type BoolParam struct {
	Metadata
}

const boolSchema = "Boolean: `true`, `1`, `yes`, `y`, `t` accepted as True; " +
	"`false`, `0`, `no`, `n`, `f` accepted (case insensitively) as False."

func (p *BoolParam) SchemaDescription() string {
	return boolSchema
}

func (p *BoolParam) Parse(raw string) (interface{}, error) {
	switch strings.ToLower(raw) {
	case "true", "1", "yes", "y", "t":
		return true, nil
	case "false", "0", "no", "n", "f":
		return false, nil
	}
	return nil, p.parseFailed(raw, "invalid boolean")
}

type BoolPtrParam struct {
	Metadata
}

func (p *BoolPtrParam) Parse(raw string) (interface{}, error) {
	t := true
	f := false
	switch strings.ToLower(raw) {
	case "true", "1", "yes", "y", "t":
		return &t, nil
	case "false", "0", "no", "n", "f":
		return &f, nil
	}
	return nil, p.parseFailed(raw, "invalid boolean")
}

func (p *BoolPtrParam) SchemaDescription() string {
	return boolSchema
}

type MinMax struct {
	Min int
	Max int
}

type IntParam struct {
	Metadata
	Ranges []MinMax
}

func (p *IntParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid int")
		return nil, err
	}
	if value < math.MinInt || value > math.MaxInt {
		err = p.parseFailed(raw, "value out of range for int type")
		return nil, err
	}
	result := int(value)
	if len(p.Ranges) == 1 {
		if result < p.Ranges[0].Min {
			err = p.parseFailed(raw,
				fmt.Sprintf("value must be at least %v", p.Ranges[0].Min))
		} else if result > p.Ranges[0].Max {
			err = p.parseFailed(raw,
				fmt.Sprintf("value must be at most %v", p.Ranges[0].Max))
		}
	} else {
		good := false
		for _, r := range p.Ranges {
			if result >= r.Min && result <= r.Max {
				good = true
				break
			}
		}
		if !good {
			msg := "value must be one of"
			for _, r := range p.Ranges {
				if r.Min == r.Max {
					msg = msg + fmt.Sprintf(" %v", r.Min)
				} else {
					msg = msg + fmt.Sprintf(" %v-%v", r.Min, r.Max)
				}
			}
			err = p.parseFailed(raw, msg)
		}
	}
	return result, err
}

func (p *IntParam) SchemaDescription() string {
	if len(p.Ranges) > 0 {
		return intSchema(p.Ranges)
	} else {
		return intSchema([]MinMax{{math.MinInt32, math.MaxInt32}})
	}
}

func intSchema(ranges []MinMax) string {
	if len(ranges) == 1 && ranges[0].Min == math.MinInt && ranges[0].Max == math.MaxInt {
		// Avoid printing the default range, which is ridiculously large for
		// most fields.
		return "Integer"
	}
	desc := "Integer: "
	first := true
	for _, r := range ranges {
		if !first {
			desc = desc + ", "
		} else {
			first = false
		}
		desc = desc + fmt.Sprintf("[%v,%v]", formatInt(r.Min), formatInt(r.Max))
	}
	return desc
}

func formatInt(m int) string {
	switch int64(m) {
	case math.MaxInt64:
		return "2^63-1"
	case math.MinInt64:
		return "-2^63"
	}
	return fmt.Sprint(m)
}

type Int32Param struct {
	Metadata
}

func (p *Int32Param) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseInt(raw, 0, 32)
	if err != nil {
		err = p.parseFailed(raw, "invalid 32-bit int")
		return nil, err
	}
	result := int32(value)
	return result, err
}

func (p *Int32Param) SchemaDescription() string {
	return intSchema([]MinMax{{math.MinInt32, math.MaxInt32}})
}

type FloatParam struct {
	Metadata
}

func (p *FloatParam) Parse(raw string) (result interface{}, err error) {
	result, err = strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	return
}

func (p *FloatParam) SchemaDescription() string {
	return "Floating point number"
}

type SecondsParam struct {
	Metadata
	Min int
	Max int
}

func (p *SecondsParam) Parse(raw string) (result interface{}, err error) {
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	result = time.Duration(seconds * float64(time.Second))
	if int(seconds) < p.Min {
		err = p.parseFailed(raw, fmt.Sprintf("value must be at least %v", p.Min))
	} else if int(seconds) > p.Max {
		err = p.parseFailed(raw, fmt.Sprintf("value must be at most %v", p.Max))
	}
	return result, err
}

func (p *SecondsParam) SchemaDescription() string {
	desc := "Seconds (floating point)"
	if p.Min != math.MinInt || p.Max != math.MaxInt {
		desc = desc + fmt.Sprintf(" between %v and %v", p.Min, p.Max)
	}
	return desc
}

type MillisParam struct {
	Metadata
}

func (p *MillisParam) Parse(raw string) (result interface{}, err error) {
	millis, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		err = p.parseFailed(raw, "invalid float")
		return
	}
	result = time.Duration(millis * float64(time.Millisecond))
	return
}

func (p *MillisParam) SchemaDescription() string {
	return "Milliseconds (floating point)"
}

type RegexpParam struct {
	Metadata
	Regexp *regexp.Regexp
	Msg    string
}

func (p *RegexpParam) Parse(raw string) (result interface{}, err error) {
	if !p.Regexp.MatchString(raw) {
		err = p.parseFailed(raw, p.Msg)
	} else {
		result = raw
	}
	return
}

func (p *RegexpParam) SchemaDescription() string {
	if p.Regexp == StringRegexp {
		return "String"
	}
	return fmt.Sprintf("String matching regex `%s`", p.Regexp.String())
}

// RegexpPatternParam differs from RegexpParam (above) in that it validates
// string values that are (themselves) regular expressions.
type RegexpPatternParam struct {
	Metadata
	Flags []string
}

// Parse validates whether the given raw string contains a valid regexp pattern.
func (p *RegexpPatternParam) Parse(raw string) (interface{}, error) {
	var result *regexp.Regexp
	if raw == "" {
		for _, f := range p.Flags {
			if f == "nil-on-empty" {
				return nil, nil
			}
		}
	}
	result, compileErr := regexp.Compile(raw)
	if compileErr != nil {
		return nil, p.parseFailed(raw, "invalid regexp")
	}
	return result, nil
}

func (p *RegexpPatternParam) SchemaDescription() string {
	return "Regular expression"
}

// RegexpPatternListParam differs from RegexpParam (above) in that it validates
// string values that are (themselves) regular expressions.
type RegexpPatternListParam struct {
	Metadata
	RegexpElemRegexp    *regexp.Regexp
	NonRegexpElemRegexp *regexp.Regexp
	Delimiter           string
	Msg                 string
	Schema              string
}

// Parse validates whether the given raw string contains a list of valid values.
// Validation is dictated by two regexp patterns: one for valid regular expression
// values, another for non-regular expressions.
func (p *RegexpPatternListParam) Parse(raw string) (interface{}, error) {
	var result []*regexp.Regexp
	// Split into individual elements, then validate each one and compile to regexp
	tokens := strings.Split(raw, p.Delimiter)
	for _, t := range tokens {
		if p.RegexpElemRegexp.MatchString(t) {
			// Need to remove the start and end symbols that wrap the actual regexp
			// Note: There's a coupling here with the assumed pattern in RegexpElemRegexp
			// i.e. that each value is wrapped by a single char symbol on either side
			regexpValue := t[1 : len(t)-1]
			compiledRegexp, compileErr := regexp.Compile(regexpValue)
			if compileErr != nil {
				return nil, p.parseFailed(raw, p.Msg)
			}
			result = append(result, compiledRegexp)
		} else if p.NonRegexpElemRegexp.MatchString(t) {
			compiledRegexp, compileErr := regexp.Compile("^" + regexp.QuoteMeta(t) + "$")
			if compileErr != nil {
				return nil, p.parseFailed(raw, p.Msg)
			}
			result = append(result, compiledRegexp)
		} else {
			return nil, p.parseFailed(raw, p.Msg)
		}
	}
	return result, nil
}

func (p *RegexpPatternListParam) SchemaDescription() string {
	return p.Schema
}

type FileParam struct {
	Metadata
	MustExist  bool
	Executable bool
}

func (p *FileParam) Parse(raw string) (interface{}, error) {
	// Use GetHostPath to use/resolve the CONTAINER_SANDBOX_MOUNT_POINT env var
	// if running on Windows HPC.
	// FIXME: this will no longer be needed when containerd v1.6 is EOL'd
	raw = winutils.GetHostPath(raw)

	if p.Executable {
		// Special case: for executable files, we search our directory
		// and the system path.
		logCxt := log.WithField("name", raw)
		var path string
		if myDir, err := osext.ExecutableFolder(); err == nil {
			logCxt.WithField("myDir", myDir).Info(
				"Looking for executable in my directory")
			path = myDir + string(os.PathSeparator) + raw
			stat, err := os.Stat(path)
			if err == nil {
				if m := stat.Mode(); !m.IsDir() && m&0111 > 0 {
					return path, nil
				}
			} else {
				logCxt.WithField("myDir", myDir).Info(
					"No executable in my directory")
				path = ""
			}
		} else {
			logCxt.WithError(err).Warn("Failed to get my dir")
		}
		if path == "" {
			logCxt.Info("Looking for executable on path")
			var err error
			path, err = exec.LookPath(raw)
			if err != nil {
				logCxt.WithError(err).Warn("Path lookup failed")
				path = ""
			}
		}
		if path == "" && p.MustExist {
			log.Error("Executable missing")
			return nil, p.parseFailed(raw, "missing file")
		}
		log.WithField("path", path).Info("Executable path")
		return path, nil
	} else if p.MustExist && raw != "" {
		log.WithField("path", raw).Info("Looking for required file")
		_, err := os.Stat(raw)
		if err != nil {
			log.Errorf("Failed to access %v: %v", raw, err)
			return nil, p.parseFailed(raw, "failed to access file")
		}
	}
	return raw, nil
}

func (p *FileParam) SchemaDescription() string {
	mustExist := ""
	if p.MustExist {
		mustExist = ", which must exist"
	}
	if p.Executable {
		return "Path to executable" + mustExist + ". If not an absolute path, " +
			"the directory containing this binary and the system path will be searched."
	}
	return "Path to file" + mustExist
}

type Ipv4Param struct {
	Metadata
}

func (p *Ipv4Param) Parse(raw string) (result interface{}, err error) {
	res := net.ParseIP(raw)
	if res == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	if !utils.IsIPv4(res) {
		err = p.parseFailed(raw, "not an IPv4 address")
	}
	result = res
	return
}

func (p *Ipv4Param) SchemaDescription() string {
	return "IPv4 address"
}

type Ipv6Param struct {
	Metadata
}

func (p *Ipv6Param) Parse(raw string) (result interface{}, err error) {
	res := net.ParseIP(raw)
	if res == nil {
		err = p.parseFailed(raw, "invalid IP")
	}
	if !utils.IsIPv6(res) {
		err = p.parseFailed(raw, "not an IPv6 address")
	}
	result = res
	return
}

func (p *Ipv6Param) SchemaDescription() string {
	return "IPv6 address"
}

type PortListParam struct {
	Metadata
}

func (p *PortListParam) Parse(raw string) (interface{}, error) {
	var result []ProtoPort
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
			return nil, p.parseFailed(raw,
				"ports should be <protocol>:<net>:<number> or <protocol>:<number> or <number>")
		}

		if len(parts) > 2 {
			netStr = parts[1]
			protocolStr = strings.ToLower(parts[0])
			portStr = parts[2]
		}

		if len(parts) == 2 {
			protocolStr = strings.ToLower(parts[0])
			portStr = parts[1]
		}

		if protocolStr != "tcp" && protocolStr != "udp" {
			return nil, p.parseFailed(raw, "unknown protocol: "+protocolStr)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			err = p.parseFailed(raw, "ports should be integers")
			return nil, err
		}
		if port < 0 || port > 65535 {
			err = p.parseFailed(raw, "ports must be in range 0-65535")
			return nil, err
		}

		protoPort := ProtoPort{
			Protocol: protocolStr,
			Port:     uint16(port),
		}

		if netStr != "" {
			_, netParsed, err := cnet.ParseCIDROrIP(netStr)
			if err != nil {
				err = p.parseFailed(raw, "invalid CIDR or IP "+netStr)
				return nil, err
			}
			protoPort.Net = netParsed.String()
		}

		result = append(result, protoPort)
	}
	return result, nil
}

func (p *PortListParam) SchemaDescription() string {
	return "Comma-delimited list of numeric ports with optional protocol and CIDR:" +
		"`(tcp|udp):<cidr>:<port>`, `(tcp|udp):<port>` or `<port>`. IPv6 " +
		"CIDRs must be enclosed in square brackets."
}

type PortRangeParam struct {
	Metadata
}

func (p *PortRangeParam) Parse(raw string) (interface{}, error) {
	portRange, err := numorstring.PortFromString(raw)
	if err != nil {
		return nil, p.parseFailed(raw, fmt.Sprintf("%s is not a valid port range", raw))
	}
	if len(portRange.PortName) > 0 {
		return nil, p.parseFailed(raw, fmt.Sprintf("%s has port name set", raw))
	}
	return portRange, nil
}

func (p *PortRangeParam) SchemaDescription() string {
	return "Port range: either a single number in [0,65535] or a range of numbers `n:m`"
}

type PortRangeListParam struct {
	Metadata
}

func (p *PortRangeListParam) Parse(raw string) (interface{}, error) {
	var result []numorstring.Port
	for _, rangeStr := range strings.Split(raw, ",") {
		portRange, err := numorstring.PortFromString(rangeStr)
		if err != nil {
			return nil, p.parseFailed(raw, fmt.Sprintf("%s is not a valid port range", rangeStr))
		}
		if len(portRange.PortName) > 0 {
			return nil, p.parseFailed(raw, fmt.Sprintf("%s has port name set", rangeStr))
		}
		result = append(result, portRange)
	}
	return result, nil
}

func (p *PortRangeListParam) SchemaDescription() string {
	return "List of port ranges: comma-delimited list of either single numbers in range [0,65535] or a ranges of numbers `n:m`"
}

type EndpointListParam struct {
	Metadata
}

func (p *EndpointListParam) Parse(raw string) (result interface{}, err error) {
	value := strings.Split(raw, ",")
	scheme := ""
	resultSlice := []string{}
	for _, endpoint := range value {
		endpoint = strings.Trim(endpoint, " ")
		if len(endpoint) == 0 {
			continue
		}
		var u *url.URL
		u, err = url.Parse(endpoint)
		if err != nil {
			err = p.parseFailed(raw,
				fmt.Sprintf("%v is not a valid URL", endpoint))
			return
		}
		if scheme != "" && u.Scheme != scheme {
			err = p.parseFailed(raw,
				"all endpoints must have the same scheme")
			return
		}
		if u.Path == "" {
			u.Path = "/"
		}
		if u.Opaque != "" || u.User != nil || u.Path != "/" ||
			u.RawPath != "" || u.RawQuery != "" ||
			u.Fragment != "" {
			log.WithField("url", fmt.Sprintf("%#v", u)).Error(
				"Unsupported URL part")
			err = p.parseFailed(raw,
				"endpoint contained unsupported URL part; "+
					"expected http(s)://hostname:port only.")
			return
		}
		resultSlice = append(resultSlice, u.String())
	}
	result = resultSlice
	return
}

func (p *EndpointListParam) SchemaDescription() string {
	return "List of HTTP endpoints: comma-delimited list of `http(s)://hostname:port`"
}

type MarkBitmaskParam struct {
	Metadata
}

func (p *MarkBitmaskParam) Parse(raw string) (interface{}, error) {
	value, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		log.Warningf("Failed to parse %#v as an int: %v", raw, err)
		err = p.parseFailed(raw, "invalid mark: should be 32-bit int")
		return nil, err
	}
	result := uint32(value)
	bitCount := uint32(0)
	for i := uint(0); i < 32; i++ {
		bit := (result >> i) & 1
		bitCount += bit
	}
	if bitCount < MinIptablesMarkBits {
		err = p.parseFailed(raw,
			fmt.Sprintf("invalid mark: needs to have %v bits set",
				MinIptablesMarkBits))
	}
	return result, err
}

func (p *MarkBitmaskParam) SchemaDescription() string {
	return fmt.Sprintf("32-bit bitmask (hex or deccimal allowed) with at least %d bits set, example: `0xffff0000`", MinIptablesMarkBits)
}

type OneofListParam struct {
	Metadata
	lowerCaseOptionsToCanonical map[string]string
}

func (p *OneofListParam) Parse(raw string) (result interface{}, err error) {
	result, ok := p.lowerCaseOptionsToCanonical[strings.ToLower(raw)]
	if !ok {
		err = p.parseFailed(raw, "unknown option")
	}
	return
}

func (p *OneofListParam) SchemaDescription() string {
	var values []string
	for _, v := range p.lowerCaseOptionsToCanonical {
		values = append(values, fmt.Sprintf("`%s`", v))
	}
	sort.Strings(values)
	return "One of: " + strings.Join(values, ", ") + " (case insensitive)"
}

type CIDRListParam struct {
	Metadata
}

func (c *CIDRListParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("CIDRs raw", raw).Info("CIDRList")
	values := strings.Split(raw, ",")
	resultSlice := []string{}
	for _, in := range values {
		val := strings.Trim(in, " ")
		if len(val) == 0 {
			continue
		}
		_, net, e := cnet.ParseCIDROrIP(val)
		if e != nil {
			err = c.parseFailed(in, "invalid CIDR or IP "+val)
			return
		}
		resultSlice = append(resultSlice, net.String())
	}
	return resultSlice, nil
}

func (c *CIDRListParam) SchemaDescription() string {
	return "Comma-delimited list of CIDRs"
}

type ServerListParam struct {
	Metadata
}

const k8sServicePrefix = "k8s-service:"

func (c *ServerListParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("raw", raw).Info("ServerList")
	values := strings.Split(raw, ",")
	resultSlice := []ServerPort{}
	for _, in := range values {
		val := strings.TrimSpace(in)
		if len(val) == 0 {
			continue
		}
		port := 53
		portStr := ""
		if strings.HasPrefix(val, k8sServicePrefix) {
			svcName := val[len(k8sServicePrefix):]
			namespace := "kube-system"
			if slash := strings.Index(svcName, "/"); slash >= 0 {
				namespace = svcName[:slash]
				svcName = svcName[slash+1:]
			}
			if colon := strings.Index(svcName, ":"); colon >= 0 {
				portStr = svcName[colon+1:]
				svcName = svcName[:colon]
			}
			svc, e := GetKubernetesService(namespace, svcName)
			if e != nil {
				// Warn but don't report parse failure, so that other trusted IPs
				// can still take effect.
				log.Warningf("Couldn't get Kubernetes service '%v': %v", svcName, e)
				continue
			}
			val = svc.Spec.ClusterIP
			if val == "" {
				// Ditto.
				log.Warningf("Kubernetes service '%v' has no ClusterIP", svcName)
				continue
			}
			if len(svc.Spec.Ports) > 0 {
				port = int(svc.Spec.Ports[0].Port)
			}
		} else {
			// 10.25.3.4
			// 10.25.3.4:536
			// [fd10:25::2]:536
			// fd10:25::2
			if colon := strings.Index(val, "]:"); colon >= 0 {
				// IPv6 address with port number.
				portStr = val[colon+2:]
				val = val[1:colon]
			} else if colon := strings.Index(val, ":"); colon >= 0 && strings.Count(val, ":") == 1 {
				// IPv4 address with port number.
				portStr = val[colon+1:]
				val = val[:colon]
			}
			if net.ParseIP(val) == nil {
				err = c.parseFailed(in, "invalid server IP '"+val+"'")
				return
			}
		}
		if portStr != "" {
			port, err = strconv.Atoi(portStr)
			if err != nil {
				err = c.parseFailed(in, "invalid port '"+portStr+"': "+err.Error())
				return
			}
		}
		if port < 0 || port > math.MaxUint16 {
			err = c.parseFailed(in, fmt.Sprintf("invalid port %d: should be between 0 and 65535", port))
			return
		}
		resultSlice = append(resultSlice, ServerPort{IP: val, Port: uint16(port)})
	}
	return resultSlice, nil
}

func (c *ServerListParam) SchemaDescription() string {
	return "Comma-delimited list of DNS servers. Each entry can be: " +
		"`<IP address>`, an `<IP address>:<port>` (IPv6 addresses must be " +
		"wrapped in square brackets), or, a Kubernetes service name " +
		"`k8s-service:(namespace/)service-name`."
}

func realGetKubernetesService(namespace, svcName string) (*v1.Service, error) {
	// Try to get the kubernetes config either from environments or in-cluster.
	// Note: Felix on Windows does not run as a Pod hence no in-cluster config is available.
	// Attempt in-cluster config first.
	// FIXME: get rid of this and call rest.InClusterConfig() directly when containerd v1.6 is EOL'd
	k8scfg, err := winutils.GetInClusterConfig()
	if err != nil {
		log.WithError(err).Info("Unable to create in-cluster Kubernetes config, attemping environments instead")

		cfgFile := os.Getenv("KUBECONFIG")
		// Host env vars may override the container on Windows HPC, so $env:KUBECONFIG cannot
		// be trusted in this case
		// FIXME: this will no longer be needed when containerd v1.6 is EOL'd
		if winutils.InHostProcessContainer() {
			cfgFile = ""
		}
		master := os.Getenv("KUBERNETES_MASTER")
		// FIXME: get rid of this and call clientcmd.BuildConfigFromFlags() directly when containerd v1.6 is EOL'd
		k8scfg, err = winutils.BuildConfigFromFlags(master, cfgFile)
		if err != nil {
			log.WithError(err).Errorf("Unable to create Kubernetes config.")
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(k8scfg)
	if err != nil {
		log.WithError(err).Error("Unable to create Kubernetes client set.")
		return nil, err
	}
	svcClient := clientset.CoreV1().Services(namespace)
	return svcClient.Get(context.Background(), svcName, metav1.GetOptions{})
}

var GetKubernetesService = realGetKubernetesService

type RegionParam struct {
	Metadata
}

const regionNamespacePrefix = "openstack-region-"
const maxRegionLength int = validation.DNS1123LabelMaxLength - len(regionNamespacePrefix)

func (r *RegionParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("raw", raw).Info("Region")
	if len(raw) > maxRegionLength {
		err = fmt.Errorf("the value of OpenstackRegion must be %v chars or fewer", maxRegionLength)
		return
	}
	errs := validation.IsDNS1123Label(raw)
	if len(errs) != 0 {
		msg := "The value of OpenstackRegion must be a valid DNS label"
		for _, err := range errs {
			msg = msg + "; " + err
		}
		err = errors.New(msg)
		return
	}
	return raw, nil
}

func (r *RegionParam) SchemaDescription() string {
	return "OpenStack region name (must be a valid DNS label)"
}

// linux can support route-table indices up to 0xFFFFFFFF
// however, using 0xFFFFFFFF tables would require too much computation, so the total number of designated tables is capped at 0xFFFF
const routeTableMaxLinux uint32 = 0xffffffff
const routeTableRangeMaxTables = 0xffff

type RouteTableRangeParam struct {
	Metadata
}

func (p *RouteTableRangeParam) Parse(raw string) (result interface{}, err error) {
	err = p.parseFailed(raw, "must be a range of route table indices within 1-250")
	m := regexp.MustCompile(`^(\d+)-(\d+)$`).FindStringSubmatch(raw)
	if m == nil {
		return
	}
	min, serr := strconv.Atoi(m[1])
	if serr != nil {
		return
	}
	max, serr := strconv.Atoi(m[2])
	if serr != nil {
		return
	}
	if min >= 1 && max >= min && max <= 250 {
		result = idalloc.IndexRange{Min: min, Max: max}
		err = nil
	}
	return
}

func (p *RouteTableRangeParam) SchemaDescription() string {
	return "Range of route table indices `n-m`, where `n` and `m` are integers in [0,250]."
}

type RouteTableRangesParam struct {
	Metadata
}

// reserved linux kernel routing tables (will be ignored if targeted by routetablerange)
var routeTablesReservedLinux = []int{253, 254, 255}

func (p *RouteTableRangesParam) Parse(raw string) (result interface{}, err error) {
	match := regexp.MustCompile(`(\d+)-(\d+)`).FindAllStringSubmatch(raw, -1)
	if match == nil {
		err = p.parseFailed(raw, "must be a list of route-table ranges")
		return
	}

	var tablesTargeted uint
	ranges := make([]idalloc.IndexRange, 0)
	for _, r := range match {
		// first match is the whole matching string - we only care about submatches
		min, serr := strconv.Atoi(r[1])
		if serr != nil || min <= 0 {
			err = p.parseFailed(raw, "min value is not a valid number")
			return
		}
		max, serr := strconv.Atoi(r[2])
		if serr != nil {
			err = p.parseFailed(raw, "max value is not a valid number")
			return
		}
		// max val must be greater than min val
		if min > max {
			err = p.parseFailed(raw, "min value is greater than max value")
			return
		}

		if int64(max) > int64(routeTableMaxLinux) {
			err = p.parseFailed(raw, "max value is too high")
			return
		}

		// The number of route table IDs in the current range.
		rangeLen := uint(max - min + 1)

		// Overflow-safe addition
		var carry uint
		if tablesTargeted, carry = bits.Add(tablesTargeted, rangeLen, 0); carry != 0 || tablesTargeted > routeTableRangeMaxTables {
			err = p.parseFailed(raw, "targets too many tables")
			return
		}

		// check if ranges collide with reserved linux tables
		includesReserved := false
		for _, rsrv := range routeTablesReservedLinux {
			if min <= rsrv && max >= rsrv {
				includesReserved = true
			}
		}
		if includesReserved {
			log.Infof("Felix route-table range includes reserved Linux tables, values 253-255 will be ignored.")
		}

		ranges = append(ranges, idalloc.IndexRange{Min: min, Max: max})
	}

	result = ranges
	return
}

func (p *RouteTableRangesParam) SchemaDescription() string {
	return fmt.Sprintf("Comma or space-delimited list of route table ranges of the form `n-m` "+
		"where `n` and `m` are integers in [0,%d]. The sum of the sizes of all ranges may not exceed %d.",
		routeTableMaxLinux, routeTableRangeMaxTables)
}

type KeyValueListParam struct {
	Metadata
}

func (p *KeyValueListParam) Parse(raw string) (result interface{}, err error) {
	result, err = stringutils.ParseKeyValueList(raw)
	return
}

func (p *KeyValueListParam) SchemaDescription() string {
	return "Comma-delimited list of key=value pairs"
}

type KeyDurationListParam struct {
	Metadata
}

func (p *KeyDurationListParam) Parse(raw string) (result interface{}, err error) {
	result, err = stringutils.ParseKeyDurationList(raw)
	return
}

func (p *KeyDurationListParam) SchemaDescription() string {
	return "Comma-delimited list of `<key>=<duration>` pairs, where durations " +
		"use Go's standard format (e.g. 1s, 1m, 1h3m2s)"
}

type StringSliceParam struct {
	Metadata
	ValidationRegex *regexp.Regexp
}

func (p *StringSliceParam) Parse(raw string) (result interface{}, err error) {
	log.WithField("StringSliceParam raw", raw).Info("StringSliceParam")
	values := strings.Split(raw, ",")

	resultSlice := []string{}
	for _, in := range values {
		val := strings.Trim(in, " ")
		if len(val) == 0 {
			continue
		}

		// Validate string slice entry as necessary.
		if p.ValidationRegex != nil {
			match := p.ValidationRegex.MatchString(val)
			if !match {
				err = p.parseFailed(raw,
					fmt.Sprintf("invalid entry does not match regex %s", p.ValidationRegex.String()))
				return
			}
		}

		resultSlice = append(resultSlice, val)
	}

	return resultSlice, nil
}

func (p *StringSliceParam) SchemaDescription() string {
	if p.ValidationRegex == nil {
		return "Comma-delimited list of strings"
	}
	return fmt.Sprintf("Comma-delimited list of strings, each matching the regex `%s`", p.ValidationRegex.String())
}
