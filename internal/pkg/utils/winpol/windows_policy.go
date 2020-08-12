// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
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

// This package contains algorithmic support code for Windows.  I.e. code that is used on
// Windows but can be UTed on any platform.
package winpol

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/sirupsen/logrus"
)

type PolicyMarshaller interface {
	MarshalPolicies() []json.RawMessage
}

// CalculateEndpointPolicies augments the hns.Netconf policies with NAT exceptions for our IPAM blocks.
func CalculateEndpointPolicies(
	n PolicyMarshaller,
	extraNATExceptions []*net.IPNet,
	natOutgoing bool,
	mgmtIP net.IP,
	logger *logrus.Entry,
) ([]json.RawMessage, error) {
	inputPols := n.MarshalPolicies()
	var outputPols []json.RawMessage
	found := false
	for _, inPol := range inputPols {
		// Decode the raw policy as a dict so we can inspect it without losing any fields.
		decoded := map[string]interface{}{}
		err := json.Unmarshal(inPol, &decoded)
		if err != nil {
			logger.WithError(err).Error("MarshalPolicies() returned bad JSON")
			return nil, err
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
		if strings.EqualFold(decoded["Type"].(string), "OutBoundNAT") {
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
				return nil, err
			}
			logger.WithField("policy", string(outPol)).Debug(
				"Updated OutBoundNAT policy to add Calico IP pools.")
		}
		outputPols = append(outputPols, outPol)
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
			return nil, err
		}

		outputPols = append(outputPols, json.RawMessage(encoded))
	}

	// Add an entry to force encap to the management IP.  We think this is required for node ports.  The encap is
	// local to the host so there's no real vxlan going on here.
	dict := map[string]interface{}{
		"Type":              "ROUTE",
		"DestinationPrefix": mgmtIP.String() + "/32",
		"NeedEncap":         true,
	}
	encoded, err := json.Marshal(dict)
	if err != nil {
		logger.WithError(err).Error("Failed to add outbound NAT exclusion.")
		return nil, err
	}

	outputPols = append(outputPols, json.RawMessage(encoded))

	return outputPols, nil
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
