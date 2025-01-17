// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

package metrics

import (
	"bufio"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func init() {
	http.DefaultClient.Timeout = 1 * time.Second
}

var CnxPort = 9092

func CnxPortString() string {
	return strconv.Itoa(CnxPort)
}

/*
# HELP cnx_policy_rule_bytes Total number of bytes handled by CNX policy rules.
# TYPE cnx_policy_rule_bytes counter
cnx_policy_rule_bytes{namespace="test",policy="default",rule_direction="ingress",rule_index="0",tier="profile",traffic_direction="inbound"} 25
# HELP cnx_policy_rule_connections Total number of connections handled by CNX policy rules.
# TYPE cnx_policy_rule_connections gauge
cnx_policy_rule_connections{namespace="test",policy="default",rule_direction="ingress",rule_index="0",tier="profile",traffic_direction="inbound"} 25
# HELP cnx_policy_rule_packets Total number of packets handled by CNX policy rules.
# TYPE cnx_policy_rule_packets counter
cnx_policy_rule_packets{action="allow",namespace="fv",policy="policy-1",rule_direction="ingress",rule_index="0",tier="default",traffic_direction="inbound"} 81
cnx_policy_rule_packets{action="deny",namespace="fv",policy="policy-icmp",rule_direction="ingress",rule_index="0",tier="tier-1",traffic_direction="outbound"} 1
# HELP calico_denied_packets Total number of packets denied by calico Policies.
# TYPE calico_denied_packets gauge
calico_denied_packets{policy="tier1|fv/policy-1|0|deny|-1",srcIP="10.245.13.133"} 5
*/
func GetCNXMetrics(felixIP, name string) (metricLines []string, err error) {
	var resp *http.Response
	resp, err = http.Get("http://" + felixIP + ":" + CnxPortString() + "/metrics")
	if err != nil {
		return
	}
	log.WithField("resp", resp).Debug("Metric response")
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		log.WithField("line", line).Debug("Line")
		if strings.HasPrefix(line, name) {
			log.WithField("line", line).Info("Line")
			metricLines = append(metricLines, strings.TrimSpace(strings.TrimPrefix(line, name)))
		}
	}
	err = scanner.Err()
	return
}

// GetCNXConnectionMetricsIntForPolicy returns the total number of connections associated with a
// policy for a specific traffic direction. You may optionally specify a rule index.
func GetCNXConnectionMetricsIntForPolicy(felixIP, tierName, policyName, trafficDirection string, ruleIdx ...int) (sum int, err error) {
	lines, err := GetCNXMetrics(felixIP, "cnx_policy_rule_connections")
	if err != nil {
		return
	}
	tierName = "tier=\"" + tierName + "\""
	policyName = "policy=\"" + policyName + "\""
	trafficDirection = "traffic_direction=\"" + trafficDirection + "\""
	ruleIdxStr := ""
	if len(ruleIdx) > 0 {
		ruleIdxStr = fmt.Sprintf("rule_index=\"%d\"", ruleIdx[0])
	}
	s := 0
	for _, line := range lines {
		if strings.Contains(line, tierName) && strings.Contains(line, policyName) &&
			strings.Contains(line, trafficDirection) && strings.Contains(line, ruleIdxStr) {
			words := strings.Split(line, " ")
			s, err = strconv.Atoi(strings.TrimSpace(words[1]))
			if err != nil {
				sum = 0
				return
			}
			sum += s
			log.WithFields(log.Fields{
				"converted_word": s,
				"sum":            sum,
			}).Info("Calculated sum")
		}
	}
	log.WithFields(log.Fields{
		"tier":             tierName,
		"policy":           policyName,
		"trafficDirection": trafficDirection,
		"sum":              sum,
	}).Debug("cnx_policy_rule_connections")
	return
}

// GetCNXPacketMetricsIntForPolicy returns the total number of packets associated with a
// policy for a specific traffic and rule direction. You may optionally specify a rule index.
func GetCNXPacketMetricsIntForPolicy(felixIP, action, tierName, policyName, trafficDirection, ruleDirection string, ruleIdx ...int) (sum int, err error) {
	lines, err := GetCNXMetrics(felixIP, "cnx_policy_rule_packets")
	if err != nil {
		return
	}
	action = "action=\"" + action + "\""
	tierName = "tier=\"" + tierName + "\""
	policyName = "policy=\"" + policyName + "\""
	trafficDirection = "traffic_direction=\"" + trafficDirection + "\""
	ruleDirection = "rule_direction=\"" + ruleDirection + "\""
	ruleIdxStr := ""
	if len(ruleIdx) > 0 {
		ruleIdxStr = fmt.Sprintf("rule_index=\"%d\"", ruleIdx[0])
	}
	s := 0
	for _, line := range lines {
		if strings.Contains(line, action) && strings.Contains(line, tierName) && strings.Contains(line, policyName) &&
			strings.Contains(line, trafficDirection) && strings.Contains(line, ruleDirection) && strings.Contains(line, ruleIdxStr) {
			words := strings.Split(line, " ")
			s, err = strconv.Atoi(strings.TrimSpace(words[1]))
			if err != nil {
				sum = 0
				return
			}
			sum += s
		}

	}
	log.WithFields(log.Fields{
		"action":           action,
		"tier":             tierName,
		"policy":           policyName,
		"trafficDirection": trafficDirection,
		"ruleDirection":    ruleDirection,
		"sum":              sum,
	}).Debug("cnx_policy_rule_packets")
	return
}

// GetCNXByteMetricsIntForPolicy returns the total number of bytes associated with a
// policy for a specific traffic and rule direction. You may optionally specify a rule index.
func GetCNXByteMetricsIntForPolicy(felixIP, action, tierName, policyName, trafficDirection, ruleDirection string, ruleIdx ...int) (sum int, err error) {
	lines, err := GetCNXMetrics(felixIP, "cnx_policy_rule_bytes")
	if err != nil {
		return
	}
	action = "action=\"" + action + "\""
	tierName = "tier=\"" + tierName + "\""
	policyName = "policy=\"" + policyName + "\""
	trafficDirection = "traffic_direction=\"" + trafficDirection + "\""
	ruleDirection = "rule_direction=\"" + ruleDirection + "\""
	ruleIdxStr := ""
	if len(ruleIdx) > 0 {
		ruleIdxStr = fmt.Sprintf("rule_index=\"%d\"", ruleIdx[0])
	}
	s := 0
	for _, line := range lines {
		if strings.Contains(line, action) && strings.Contains(line, tierName) && strings.Contains(line, policyName) &&
			strings.Contains(line, trafficDirection) && strings.Contains(line, ruleDirection) && strings.Contains(line, ruleIdxStr) {
			words := strings.Split(line, " ")
			s, err = strconv.Atoi(strings.TrimSpace(words[1]))
			if err != nil {
				sum = 0
				return
			}
			sum += s
		}

	}
	log.WithFields(log.Fields{
		"action":           action,
		"tier":             tierName,
		"policy":           policyName,
		"trafficDirection": trafficDirection,
		"ruleDirection":    ruleDirection,
		"sum":              sum,
	}).Debug("cnx_policy_rule_bytes")
	return
}

func GetCalicoDeniedPacketMetrics(felixIP, tierName, policyName string) (sum int, err error) {
	lines, err := GetCNXMetrics(felixIP, "calico_denied_packets")
	if err != nil {
		return
	}
	s := 0
	for _, line := range lines {
		if strings.Contains(line, tierName) && strings.Contains(line, policyName) {
			words := strings.Split(line, " ")
			s, err = strconv.Atoi(strings.TrimSpace(words[1]))
			if err != nil {
				sum = 0
				return
			}
			sum += s
		}
	}
	log.WithFields(log.Fields{
		"tier":   tierName,
		"policy": policyName,
		"sum":    sum,
	}).Debug("calico_denied_packets")
	return
}
