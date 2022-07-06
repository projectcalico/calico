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
	"io/ioutil"
	"os"
	"strings"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/asm"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// policyCmd represents the counters command
var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Dump policy attached to interface",
}

func init() {
	policyCmd.AddCommand(policyDumpCmd)
	rootCmd.AddCommand(policyCmd)

}

var policyDumpCmd = &cobra.Command{
	Use:   "dump <interface> <hook>",
	Short: "dumps policy",
	Run: func(cmd *cobra.Command, args []string) {
		iface, hook, err := parseArgs(args)
		if err != nil {
			log.WithError(err).Error("Failed to dump policy info.")
			return
		}
		hooks := []string{}
		if hook == "all" {
			hooks = []string{"ingress", "egress"}
		} else {
			hooks = append(hooks, hook)
		}

		for _, dir := range hooks {
			err := dumpPolicyInfo(cmd, iface, dir)
			if err != nil {
				log.WithError(err).Error("Failed to dump policy info.")
			}
		}
	},
}

func parseArgs(args []string) (string, string, error) {
	if len(args) != 2 {
		return "", "", fmt.Errorf("Insufficient arguments")
	}
	if (args[1] != "ingress" && args[1] != "egress" && args[1] != "all") || args[0] == "" {
		return "", "", fmt.Errorf("Invalid argument")
	}
	return args[0], args[1], nil
}

func printInsn(cmd *cobra.Command, insn asm.Insn) {
	cmd.Printf("      ")
	for _, value := range insn.Instruction {
		cmd.Printf("%02x", value)
	}
	cmd.Printf(" %v\n", insn)
}

func dumpPolicyInfo(cmd *cobra.Command, iface, hook string) error {
	var policyDbg bpf.PolicyDebugInfo
	filename := bpf.PolicyDebugJSONFileName(iface, hook)
	_, err := os.Stat(filename)
	if err != nil {
		return err
	}

	jsonFile, err := os.Open(filename)
	if err != nil {
		return err
	}

	byteValue, _ := ioutil.ReadAll(jsonFile)
	dec := json.NewDecoder(strings.NewReader(string(byteValue)))
	err = dec.Decode(&policyDbg)
	if err != nil {
		return err
	}
	cmd.Printf("IfaceName: %s\n", policyDbg.IfaceName)
	cmd.Printf("Hook: %s\n", policyDbg.Hook)
	cmd.Println("Policy Info:")
	for _, insn := range policyDbg.PolicyInfo {
		for _, label := range insn.Labels {
			cmd.Printf("%s:\n", label)
		}
		for _, comment := range insn.Comments {
			cmd.Printf("      // %s\n", comment)
		}
		printInsn(cmd, insn)
	}
	return nil
}
