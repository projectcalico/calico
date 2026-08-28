// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type patch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// patches implements Patch.
type patches []patch

func (s *patches) Type() types.PatchType {
	return types.JSONPatchType
}

func (s *patches) Data(obj client.Object) ([]byte, error) {
	return json.Marshal(s)
}

// These env variable values are specified with no units, but the FelixConfiguration
// API uses a metav1.Duration and expects units to be present. This maps the env var
// to the assumed units to be attached to the value.
var unitlessEnvVars = map[string]string{
	"FELIX_IPTABLESREFRESHINTERVAL": "s",
}

// handleFelixVars handles unexpected felix env vars (i.e. vars that start with FELIX_*) on the calico-node container
// by patching them into the default FelixConfiguration resource.
func handleFelixVars(c *components) error {
	cn := getContainer(c.node.Spec.Template.Spec, containerCalicoNode)
	if cn == nil {
		return fmt.Errorf("missing calico-node container")
	}
	// loop through all env vars of the form 'FELIX_key=val', and convert them
	// into patches
	p := new(patches)
	for _, env := range cn.Env {
		if !strings.HasPrefix(env.Name, "FELIX_") {
			continue
		}

		// skip any value that was otherwise checked / accounted for somewhere else
		// in the migration code
		if _, ok := c.node.checkedVars[containerCalicoNode].envVars[env.Name]; ok {
			continue
		}

		fval, err := c.node.getEnv(ctx, c.client, containerCalicoNode, env.Name)
		if err != nil {
			return err
		}

		// FelixConfig's default for IptablesBackend is auto and the FelixConfig does not support
		// auto as a value so nothing to do with this case.
		if env.Name == "FELIX_IPTABLESBACKEND" && strings.ToLower(*fval) == "auto" {
			continue
		}

		// Handle env vars that need to be represented as metav1.Duration.
		if unit, ok := unitlessEnvVars[env.Name]; ok && !strings.HasSuffix(*fval, unit) {
			withUnits := fmt.Sprintf("%s%s", *fval, unit)
			fval = &withUnits
		}

		// downcase and remove FELIX_ prefix
		key := strings.ToLower(strings.TrimPrefix(env.Name, "FELIX_"))
		pp, err := patchFromVal(key, *fval)
		if err != nil {
			return err
		}
		*p = append(*p, pp)

	}

	return c.client.Patch(ctx, &v3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
	}, p)
}

func patchFromVal(key, val string) (patch, error) {
	// since env vars are caps lock, we need to get the correct casing of
	// the given env var. to do this, loop through the felixconfigspec
	// using reflection, finding the struct field where the downcased name
	// matches the downcased env var name.
	fc := reflect.ValueOf(v3.FelixConfigurationSpec{})
	for ii := 0; ii < fc.Type().NumField(); ii++ {
		field := fc.Type().Field(ii)
		value := fc.Field(ii)

		if strings.EqualFold(key, field.Name) {
			fieldName := strings.Split(field.Tag.Get("json"), ",")[0]

			v, err := convert(value.Interface(), val)
			if err != nil {
				return patch{}, err
			}

			return patch{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/%s", fieldName),
				Value: v,
			}, nil
		}
	}

	return patch{}, fmt.Errorf("unrecognized felix config setting: %v", key)
}

// convert transforms a string representation to the desired type <t>.
// the only types supported are the known types of FelixConfigurationSpec.
func convert(t interface{}, str string) (interface{}, error) {
	switch t.(type) {
	case string:
		return str, nil

	case *string:
		return &str, nil

	case *[]string:
		ss := strings.Split(str, ",")
		return &ss, nil

	case *bool:
		b, err := strconv.ParseBool(str)
		if err != nil {
			return nil, err
		}
		return &b, nil

	case *int:
		i, err := strconv.Atoi(str)
		if err != nil {
			return nil, err
		}
		return &i, nil

	case *uint32:
		i, err := strconv.ParseUint(str, 10, 32)
		if err != nil {
			return nil, err
		}
		u := uint32(i)
		return &u, nil

	case *v3.IptablesBackend:
		v := v3.IptablesBackend(str)
		return &v, nil
	case *v3.AWSSrcDstCheckOption:
		v := v3.AWSSrcDstCheckOption(str)
		return &v, nil

	case *[]v3.ProtoPort:
		pps := []v3.ProtoPort{}
		if str == "none" {
			// Failsafe ports support the value "none", which is represented as
			// an empty slice on the FelixConfiguration API.
			return &pps, nil
		}
		ppsStr := strings.Split(str, ",")
		for _, ppStr := range ppsStr {
			vals := strings.Split(ppStr, ":")
			if len(vals) != 2 {
				return nil, fmt.Errorf("could not convert protoport '%s': must be of form <proto>:<port>", ppStr)
			}
			port, err := strconv.ParseUint(vals[1], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("could not convert port to number: %s", vals[0])
			}
			pps = append(pps, v3.ProtoPort{
				Port:     uint16(port),
				Protocol: vals[0],
			})
		}
		return &pps, nil

	case *[]numorstring.Port:
		ports := []numorstring.Port{}
		strs := strings.Split(str, ",")
		for _, p := range strs {
			port, err := numorstring.PortFromString(p)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
		return &ports, nil

	case *numorstring.Port:
		v, err := numorstring.PortFromString(str)
		if err != nil {
			return nil, err
		}
		return &v, nil

	case *metav1.Duration:
		d, err := time.ParseDuration(str)
		if err != nil {
			return nil, err
		}
		return &metav1.Duration{Duration: d}, nil

	case *v3.RouteTableRange:
		minMax := strings.Split(str, "-")
		if len(minMax) != 2 {
			return nil, fmt.Errorf("")
		}
		min, err := strconv.Atoi(minMax[0])
		if err != nil {
			return nil, err
		}
		max, err := strconv.Atoi(minMax[1])
		if err != nil {
			return nil, err
		}

		return &v3.RouteTableRange{
			Min: min,
			Max: max,
		}, nil
	}

	return nil, fmt.Errorf("unrecognized type: %s", t)
}
