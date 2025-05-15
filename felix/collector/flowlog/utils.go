// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowlog

import (
	"fmt"
	"strings"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
)

const (
	FieldNotIncluded                 = "-"
	fieldNotIncludedForNumericFields = 0
	fieldAggregated                  = "*"

	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"

	ReporterSrc ReporterType = "src"
	ReporterDst ReporterType = "dst"
)

// GetActionAndReporterFromRuleID converts the action to a string value.
func getActionAndReporterFromRuleID(r *calc.RuleID) (a Action, flr ReporterType) {
	switch r.Action {
	case rules.RuleActionDeny:
		a = ActionDeny
	case rules.RuleActionAllow:
		a = ActionAllow
	}
	switch r.Direction {
	case rules.RuleDirIngress:
		flr = ReporterDst
	case rules.RuleDirEgress:
		flr = ReporterSrc
	}
	return
}

func labelsToString(labels map[string]string) string {
	if labels == nil {
		return "-"
	}
	return fmt.Sprintf("[%v]", strings.Join(utils.FlattenLabels(labels), ","))
}

func stringToLabels(labelStr string) map[string]string {
	if labelStr == "-" {
		return nil
	}
	labels := strings.Split(labelStr[1:len(labelStr)-1], ",")
	return utils.UnflattenLabels(labels)
}

func getService(svc metric.ServiceInfo) FlowService {
	if svc.Name == "" {
		return FlowService{
			Namespace: FieldNotIncluded,
			Name:      FieldNotIncluded,
			PortName:  FieldNotIncluded,
			PortNum:   fieldNotIncludedForNumericFields,
		}
	} else if svc.Port == "" { // proxy.ServicePortName.Port refers to the PortName
		// A single port for a service may not have a name.
		return FlowService{
			Namespace: svc.Namespace,
			Name:      svc.Name,
			PortName:  FieldNotIncluded,
			PortNum:   svc.PortNum,
		}
	}
	return FlowService{
		Namespace: svc.Namespace,
		Name:      svc.Name,
		PortName:  svc.Port,
		PortNum:   svc.PortNum,
	}
}
