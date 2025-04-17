// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

func main() {
	logutils.ConfigureEarlyLogging()
	// We use stdout for the parseable output of the tool so we _do_ want
	// logging to go to stderr.
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.WarnLevel)

	if len(os.Args) != 3 {
		logrus.Fatalln("Usage: calico-selector id|set-name|print-tree <selector>")
		os.Exit(1)
	}

	selStr := os.Args[2]
	sel, err := selector.Parse(selStr)
	if err != nil {
		logrus.Fatalln("Failed to parse selector:", err)
		os.Exit(1)
	}
	logrus.Info("Parsed selector:", sel.String())
	logrus.Info("Unique ID:", sel.UniqueID())

	switch os.Args[1] {
	case "id":
		fmt.Println(sel.UniqueID())
	case "set-name":
		// cali40s:buYu-wdtmS21f_KbIqrPSoG
		fmt.Println("cali40" + sel.UniqueID()[:25])
	case "print-tree":
		printTree("", sel.Root(), false)
	default:
		logrus.Fatalln("Usage: calico-selector id|set-name|print-tree <selector>")
	}
}

func printTree(indent string, n parser.Node, continueLine bool) {
	p := func(v string, args ...any) {
		fmt.Printf(indent+v+"\n", args...)
	}
	nextIndent := strings.ReplaceAll(indent, "-", " ")
	if continueLine {
		nextIndent = strings.ReplaceAll(nextIndent, "+", "|")
	} else {
		nextIndent = strings.ReplaceAll(nextIndent, "+", " ")
	}
	nextIndent += "+-"
	switch n := n.(type) {
	case *parser.AllNode:
		p("all()")
	case *parser.GlobalNode:
		p("global()")
	case *parser.LabelEqValueNode:
		p("(%s == %q)", n.LabelName, n.Value)
	case *parser.LabelNeValueNode:
		p("(%s != %q)", n.LabelName, n.Value)
	case *parser.LabelInSetNode:
		p("(%s in {%s})", n.LabelName, strings.Join(n.Value, ","))
	case *parser.LabelNotInSetNode:
		p("(%s not in {%s})", n.LabelName, strings.Join(n.Value, ","))
	case *parser.LabelStartsWithValueNode:
		p("(%s starts with %q)", n.LabelName, n.Value)
	case *parser.LabelEndsWithValueNode:
		p("(%s ends with %q)", n.LabelName, n.Value)
	case *parser.LabelContainsValueNode:
		p("(%s contains %q)", n.LabelName, n.Value)
	case *parser.HasNode:
		p("has(%s)", n.LabelName)
	case *parser.NotNode:
		p("NOT")
		printTree(nextIndent, n.Operand, false)
	case *parser.AndNode:
		p("AND")
		for i, op := range n.Operands {
			printTree(nextIndent, op, i < len(n.Operands)-1)
		}
	case *parser.OrNode:
		p("OR")
		for i, op := range n.Operands {
			printTree(nextIndent, op, i < len(n.Operands)-1)
		}
	default:
		p("unknown node type: %v", n)
	}
}
