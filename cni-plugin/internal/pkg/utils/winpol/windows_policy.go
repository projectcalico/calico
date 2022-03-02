// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
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

// This package contains algorithmic support code for Windows.  I.e. code that is used on
// Windows but can be UTed on any platform.
package winpol

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils/hcn"
)

type PolicyMarshaller interface {
	GetHNSEndpointPolicies() []json.RawMessage
}

// CalculateEndpointPolicies augments the hns.Netconf policies with NAT exceptions for our IPAM blocks.
func CalculateEndpointPolicies(
	n PolicyMarshaller,
	extraNATExceptions []*net.IPNet,
	natOutgoing bool,
	mgmtIP net.IP,
	logger *logrus.Entry,
) ([]json.RawMessage, []hcn.EndpointPolicy, error) {
	inputPols := n.GetHNSEndpointPolicies()
	var outputV1Pols []json.RawMessage
	var outputV2Pols []hcn.EndpointPolicy

	found := false
	for _, inPol := range inputPols {
		// Decode the raw policy as a dict so we can inspect it without losing any fields.
		decoded := map[string]interface{}{}
		err := json.Unmarshal(inPol, &decoded)
		if err != nil {
			logger.WithError(err).Error("GetHNSEndpointPolicies() returned bad JSON")
			return nil, nil, err
		}

		// For NAT outgoing, we're looking for an entry like this (we'll add the other IPAM pools to the list):
		//
		// {
		//   "Type":  "OutBoundNAT",
		//   "ExceptionList":  [
		//     "10.96.0.0/12"
		//   ]
		// }
		outPol := inPol
		policyType := decoded["Type"].(string)

		if strings.EqualFold(policyType, "OutBoundNAT") {
			found = true
			if !natOutgoing {
				logger.Info("NAT-outgoing disabled for this IP pool, ignoring OutBoundNAT policy from NetConf.")
				continue
			}

			excList, _ := decoded["ExceptionList"].([]interface{})
			excList = appendCIDRs(excList, extraNATExceptions)
			decoded["ExceptionList"] = excList
			outPol, err = json.Marshal(decoded)
			if err != nil {
				logger.WithError(err).Error("Failed to add outbound NAT exclusion.")
				return nil, nil, err
			}
			logger.WithField("policy", string(outPol)).Debug(
				"Updated OutBoundNAT policy to add Calico IP pools.")
		}

		outputV1Pols = append(outputV1Pols, outPol)

		// Convert v2 policy. If the conversion to V2 policy fails just log and continue.
		// OutBoundNAT "ExceptionList" field is "Exceptions" in v2.
		if strings.EqualFold(policyType, "OutBoundNAT") {
			decoded["Exceptions"] = decoded["ExceptionList"]
			delete(decoded, "ExceptionList")
		}
		v2Pol, err := convertToHcnEndpointPolicy(decoded)
		if err != nil {
			logger.WithError(err).Warnf("Failed to convert endpoint policy to HCN endpoint policy: %+v", decoded)
		} else {
			outputV2Pols = append(outputV2Pols, v2Pol)
		}
	}
	if !found && natOutgoing && len(extraNATExceptions) > 0 {
		exceptions := appendCIDRs(nil, extraNATExceptions)
		dict := map[string]interface{}{
			"Type":          "OutBoundNAT",
			"ExceptionList": exceptions,
		}
		encoded, err := json.Marshal(dict)
		if err != nil {
			logger.WithError(err).Error("Failed to add outbound NAT exclusion.")
			return nil, nil, err
		}

		outputV1Pols = append(outputV1Pols, json.RawMessage(encoded))

		// Convert v2 policy. If the conversion to V2 policy fails just log and continue.
		// OutBoundNAT "ExceptionList" field is "Exceptions" in v2.
		dict["Exceptions"] = exceptions
		delete(dict, "ExceptionList")
		v2Pol, err := convertToHcnEndpointPolicy(dict)
		if err != nil {
			logger.WithError(err).Warnf("Failed to convert endpoint policy to HCN endpoint policy: %+v", dict)
		} else {
			outputV2Pols = append(outputV2Pols, v2Pol)
		}
	}

	return outputV1Pols, outputV2Pols, nil
}

// convertToHcnEndpointPolicy converts a map representing the raw data of a V1
// policy and converts it to an HCN endpoint policy.
//
// For example, we convert from raw JSON like:
//
// {
//   "Type":  "OutBoundNAT",
//   "ExceptionList":  [
//     "10.96.0.0/12",
//     "192.168.0.0/16"
//   ]
// }
//
// to:
//
// hcn.EndpointPolicy{
//   Type: hcn.OutBoundNAT,
//   Settings: json.RawMessage(
//     []byte(`{"ExceptionList":["10.96.0.0/12","192.168.0.0/16"]}`),
//   ),
// }
func convertToHcnEndpointPolicy(policy map[string]interface{}) (hcn.EndpointPolicy, error) {
	hcnPolicy := hcn.EndpointPolicy{}

	// Get v2 policy type.
	policyType, ok := policy["Type"].(string)
	if !ok {
		return hcnPolicy, fmt.Errorf("Invalid HNS V2 endpoint policy type: %v", policy["Type"])
	}

	// Remove the Type key from the map, leaving just the policy settings
	// that we marshall.
	delete(policy, "Type")
	policySettings, err := json.Marshal(policy)
	if err != nil {
		return hcnPolicy, fmt.Errorf("Failed to marshal policy settings.")
	}
	hcnPolicy.Type = hcn.EndpointPolicyType(policyType)
	hcnPolicy.Settings = json.RawMessage(policySettings)
	return hcnPolicy, nil
}

func appendCIDRs(excList []interface{}, extraNATExceptions []*net.IPNet) []interface{} {
	for _, cidr := range extraNATExceptions {
		maskedCIDR := &net.IPNet{
			IP:   cidr.IP.Mask(cidr.Mask),
			Mask: cidr.Mask,
		}
		excList = append(excList, maskedCIDR.String())
	}
	return excList
}
