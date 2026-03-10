// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/proto"
)

// policyCmd represents the counters command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Dump policy attached to interface",
}

func init() {
	policyCmd.AddCommand(policyDumpCmd)
	policyDumpCmd.Flags().BoolP("asm", "a", false, "Includes eBPF assembler code of the policy program")
	rootCmd.AddCommand(policyCmd)
}

var policyDumpCmd = &cobra.Command{
	Use: "dump <interface> <hook>\n" +
		"\n\thook - can be 'ingress', 'egress', 'xdp' or 'all'.",
	Short: "dumps policy",
	Run: func(cmd *cobra.Command, args []string) {
		iface, h, err := parseArgs(args)
		if err != nil {
			log.WithError(err).Error("Failed to dump policy info.")
			return
		}
		var hooks []hook.Hook
		switch h {
		case "all":
			hooks = hook.All
		case "egress":
			hooks = []hook.Hook{hook.Egress}
		case "ingress":
			hooks = []hook.Hook{hook.Ingress}
		case "xdp":
			hooks = []hook.Hook{hook.XDP}
		}

		rmap := counters.PolicyMap()
		m, err := counters.LoadPolicyMap(rmap)
		if err != nil {
			log.WithError(err).Error("error loading rule counters map.")
			return
		}

		ipsetMembers := loadIPSetMembers()

		for _, dir := range hooks {
			err := dumpPolicyInfo(cmd, iface, dir, m, ipsetMembers)
			if err != nil {
				log.WithError(err).Error("Failed to dump policy info.")
			}
		}
	},
}

func parseArgs(args []string) (string, string, error) {
	lenArgs := len(args)
	if lenArgs != 2 {
		return "", "", fmt.Errorf("invalid number of arguments: %d", lenArgs)
	}
	hookArg := args[1]
	if hook.StringToHook(hookArg) == hook.Bad && hookArg != "all" {
		return "", "", fmt.Errorf("invalid argument: '%s'", hookArg)
	}
	return args[0], args[1], nil
}

func printInsn(cmd *cobra.Command, insn asm.Insn) {
	cmd.Printf("%-6s", "")
	for _, value := range insn.Instruction {
		cmd.Printf("%02x", value)
	}
	cmd.Printf(" %-80v", insn)
	if insn.Annotation != "" {
		cmd.Printf("%s", insn.Annotation)
	}
	cmd.Println()
}

func getRuleMatchID(comment string) uint64 {
	matchID := strings.Split(comment, "Rule MatchID:")[1]
	matchID = strings.Trim(matchID, " ")
	id, err := strconv.ParseUint(matchID, 0, 64)
	if err != nil {
		return 0
	}
	return id
}

// extractProtoField extracts a quoted field value from a protobuf text-format
// string. For example, extractProtoField(`action:"allow" protocol:{number:6}`, "action")
// returns "allow".
func extractProtoField(s, field string) string {
	prefix := field + `:"`
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(prefix):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// formatRuleStart converts a raw "Start of rule" comment into a readable line.
// Input:  `Start of rule policy-tcp action:"allow" protocol:{number:6}`
// Output: `Rule: policy-tcp  Action: allow`
func formatRuleStart(comment string) string {
	after := strings.TrimPrefix(comment, "Start of rule ")
	parts := strings.SplitN(after, " ", 2)
	ruleName := parts[0]
	if len(parts) == 1 {
		return "Rule: " + ruleName
	}
	action := extractProtoField(parts[1], "action")
	if action == "" {
		return "Rule: " + ruleName
	}
	return fmt.Sprintf("Rule: %s  Action: %s", ruleName, action)
}

// loadIPSetMembers reads the BPF IP set map and returns a map from set ID to
// sorted member strings (CIDRs or named ports).
func loadIPSetMembers() map[uint64][]string {
	ipsetMap := ipsets.Map()
	fromBytes := ipsets.IPSetEntryFromBytes

	if ipv6 != nil && *ipv6 {
		ipsetMap = ipsets.MapV6()
		fromBytes = ipsets.IPSetEntryV6FromBytes
	}

	if err := ipsetMap.Open(); err != nil {
		log.WithError(err).Debug("Failed to open IP sets map, IDs will not be resolved.")
		return nil
	}

	membersBySet := map[uint64][]string{}
	err := ipsetMap.Iter(func(k, v []byte) maps.IteratorAction {
		entry := fromBytes(k)
		var member string
		if entry.Protocol() == 0 {
			member = fmt.Sprintf("%s/%d", entry.Addr(), entry.PrefixLen()-64)
		} else {
			member = fmt.Sprintf("%s:%d (proto %d)", entry.Addr(), entry.Port(), entry.Protocol())
		}
		membersBySet[entry.SetID()] = append(membersBySet[entry.SetID()], member)
		return maps.IterNone
	})
	if err != nil {
		log.WithError(err).Debug("Failed to iterate IP sets map.")
		return nil
	}
	for _, v := range membersBySet {
		sort.Strings(v)
	}
	return membersBySet
}

// ipsetHexIDRegex matches hex IP set IDs like "0x1234abcd5678ef90".
var ipsetHexIDRegex = regexp.MustCompile(`0x[0-9a-fA-F]+`)

// formatIPSets converts a raw IPSets comment into a more readable form,
// resolving hex IDs to their members when available.
// Input:  `IPSets src_ip_set_ids:<0x1234>`
// Output without resolution: `IP sets: src=0x1234`
// Output with resolution:    `IP sets: src={10.0.0.0/8, 192.168.0.0/16}`
func formatIPSets(comment string, membersBySet map[uint64][]string) string {
	after := strings.TrimPrefix(comment, "IPSets ")
	// Replace the verbose field names with shorter labels.
	r := strings.NewReplacer(
		"src_ip_set_ids:<", "src=",
		"dst_ip_set_ids:<", "dst=",
		"not_src_ip_set_ids:<", "!src=",
		"not_dst_ip_set_ids:<", "!dst=",
		">", "",
		" ,", ",",
	)
	formatted := strings.TrimSpace(r.Replace(after))

	if membersBySet != nil {
		formatted = ipsetHexIDRegex.ReplaceAllStringFunc(formatted, func(hexID string) string {
			id, err := strconv.ParseUint(hexID, 0, 64)
			if err != nil {
				return hexID
			}
			members, ok := membersBySet[id]
			if !ok || len(members) == 0 {
				return hexID
			}
			return "{" + strings.Join(members, ", ") + "}"
		})
	}

	return "IP sets: " + formatted
}

// formatTierEnd converts "End of tier <name>: <action>" into a readable form.
func formatTierEnd(comment string) string {
	after := strings.TrimPrefix(comment, "End of tier ")
	parts := strings.SplitN(after, ": ", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("End Tier: %s  (action: %s)", parts[0], parts[1])
	}
	return "End Tier: " + after
}

// indent returns a string of spaces for the given nesting depth.
func indent(depth int) string {
	return strings.Repeat("  ", depth)
}

func dumpPolicyInfo(cmd *cobra.Command, iface string, h hook.Hook, m counters.PolicyMapMem, ipsetMembers map[uint64][]string) error {
	verboseFlag := cmd.Flag("asm").Value.String()
	verboseFlagSet, _ := strconv.ParseBool(verboseFlag)

	var policyDbg bpf.PolicyDebugInfo
	family := proto.IPVersion_IPV4
	if ipv6 != nil && *ipv6 {
		family = proto.IPVersion_IPV6
	}
	filename := bpf.PolicyDebugJSONFileName(iface, h.String(), family)
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	jsonFile, err := os.Open(filename)
	if err != nil {
		return err
	}

	byteValue, _ := io.ReadAll(jsonFile)
	dec := json.NewDecoder(strings.NewReader(string(byteValue)))
	err = dec.Decode(&policyDbg)
	if err != nil {
		return err
	}

	cmd.Printf("IfaceName: %s\n", policyDbg.IfaceName)
	cmd.Printf("Hook: %s\n", policyDbg.Hook)
	if policyDbg.Error != "" {
		cmd.Printf("Error: %s\n", policyDbg.Error)
	}

	// depth tracks indentation: 0=top, 1=tier, 2=policy, 3=rule
	depth := 0

	for _, insn := range policyDbg.PolicyInfo {
		for _, comment := range insn.Comments {
			switch {
			case strings.Contains(comment, "Rule MatchID"):
				matchId := getRuleMatchID(comment)
				cmd.Printf("%sHit count: %d\n", indent(depth), m[matchId])

			case strings.HasPrefix(comment, "Start of tier "):
				tierName := strings.TrimPrefix(comment, "Start of tier ")
				depth = 1
				cmd.Printf("%sTier: %s\n", indent(depth), tierName)

			case strings.HasPrefix(comment, "End of tier "):
				cmd.Printf("%s%s\n", indent(depth), formatTierEnd(comment))
				depth = 0

			case strings.HasPrefix(comment, "Start of rule "):
				depth = 3
				cmd.Printf("%s%s\n", indent(depth), formatRuleStart(comment))

			case strings.HasPrefix(comment, "End of rule "):
				depth = 2

			case strings.HasPrefix(comment, "Start of "):
				// Policy start: "Start of GlobalNetworkPolicy policy-tcp"
				policyName := strings.TrimPrefix(comment, "Start of ")
				depth = 2
				cmd.Printf("%sPolicy: %s\n", indent(depth), policyName)

			case strings.HasPrefix(comment, "End of "):
				policyName := strings.TrimPrefix(comment, "End of ")
				cmd.Printf("%sEnd Policy: %s\n", indent(depth), policyName)
				depth = 1

			case strings.HasPrefix(comment, "IPSets "):
				cmd.Printf("%s%s\n", indent(depth), formatIPSets(comment, ipsetMembers))

			case strings.HasPrefix(comment, "##### Start of program"):
				if verboseFlagSet {
					cmd.Printf("\n%s%s\n", indent(depth), comment)
				}

			default:
				if verboseFlagSet {
					cmd.Printf("%s// %s\n", indent(depth), comment)
				}
			}
		}
		for _, label := range insn.Labels {
			if verboseFlagSet {
				cmd.Printf("%s%s:\n", indent(depth), label)
			}
		}
		if verboseFlagSet {
			printInsn(cmd, insn)
		}
	}
	return nil
}
