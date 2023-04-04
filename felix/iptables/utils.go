// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/projectcalico/calico/felix/environment"
)

func InsertRulesNow(table string, chain string, rules []Rule, features environment.FeatureDetectorIface) error {
	buf := new(RestoreInputBuilder)
	buf.StartTransaction(table)
	for i, r := range rules {
		buf.WriteLine(r.RenderInsertAtRuleNumber(chain, i+1, "", features.GetFeatures()))
	}
	buf.EndTransaction()
	inputBytes := buf.GetBytesAndReset()

	return Restore(inputBytes)
}

func Restore(input []byte) error {
	cmd := exec.Command("iptables-restore", "--noflush", "--verbose", "--wait", "10", "--wait-interval", "100000")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	go func() {
		defer stdin.Close()
		reader := bytes.NewReader(input)
		reader.WriteTo(stdin)
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n\nOUTPUT:\n%s", err, string(out))
	}

	return nil
}
