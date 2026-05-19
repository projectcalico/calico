// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Generator for the counted endpointData variants.
//
// Run with `go run ./felix/labelindex/gen/endpointdata` from the repo
// root. Emits felix/labelindex/endpoint_data_impls_gen.go containing
// the 27 concrete variant types and the newCountedEndpointData
// dispatcher.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"log"
	"os"
	"strings"
	"text/template"
)

type cidrAxis struct {
	Name        string
	Fields      string
	EqualToBody string
	Init        string
	// AppendCIDROrIPBody is the body of AppendCIDROrIPMembers for this
	// CIDR shape. It must append to `buf` and reference `d`.
	AppendCIDROrIPBody string
	// AppendIPPortPerPortBody is the inner per-matching-port body of
	// AppendIPPortMembers — emitted once per known address inside the
	// variant's port loop. Must reference `buf`, `port`, `emit`.
	AppendIPPortPerPortBody string
}

type portsAxis struct {
	Name        string
	Len         int
	Fields      string
	EqualToBody string
	Init        string
	// AppendIPPortPortLoopBody is the body of AppendIPPortMembers that
	// iterates this variant's ports. Each matching port runs the
	// {{.CIDR.AppendIPPortPerPortBody}} inside an "if matched" block.
	// The template substitutes PER_PORT_BODY with the cidr axis
	// per-port body at generation time.
	AppendIPPortPortLoopBody string
}

type parentsAxis struct {
	Name           string
	Len            int
	Fields         string
	EachParentBody string
	HasParentBody  string
	EqualToBody    string
	Init           string
	// GetHandleParentScan is the body emitted inside GetHandle to walk
	// this variant's parents looking for a matching label. Must
	// reference `name` (the requested handle).
	GetHandleParentScan string
}

var cidrAxes = []cidrAxis{
	{
		Name:        "V4",
		Fields:      "\tv4 [1]ip.V4Addr\n",
		EqualToBody: "\tif d.v4 != o.v4 {\n\t\treturn false\n\t}",
		Init:        "v4: [1]ip.V4Addr{v4},",
		AppendCIDROrIPBody: "\tbuf = append(buf, ipsetmember.MakeSingleIPv4(d.v4[0]))",
		AppendIPPortPerPortBody: "\t\tbuf = append(buf, ipsetmember.MakeIPPortProtoV4(d.v4[0], port, emit))",
	},
	{
		Name:        "V6",
		Fields:      "\tv6 [1]ip.V6Addr\n",
		EqualToBody: "\tif d.v6 != o.v6 {\n\t\treturn false\n\t}",
		Init:        "v6: [1]ip.V6Addr{v6},",
		AppendCIDROrIPBody: "\tbuf = append(buf, ipsetmember.MakeSingleIPv6(d.v6[0]))",
		AppendIPPortPerPortBody: "\t\tbuf = append(buf, ipsetmember.MakeIPPortProtoV6(d.v6[0], port, emit))",
	},
	{
		Name: "Dual",
		Fields: "\tv4 [1]ip.V4Addr\n" +
			"\tv6 [1]ip.V6Addr\n",
		EqualToBody: "\tif d.v4 != o.v4 || d.v6 != o.v6 {\n\t\treturn false\n\t}",
		Init:        "v4: [1]ip.V4Addr{v4}, v6: [1]ip.V6Addr{v6},",
		AppendCIDROrIPBody: "\tbuf = append(buf, ipsetmember.MakeSingleIPv4(d.v4[0]))\n" +
			"\tbuf = append(buf, ipsetmember.MakeSingleIPv6(d.v6[0]))",
		AppendIPPortPerPortBody: "\t\tbuf = append(buf, ipsetmember.MakeIPPortProtoV4(d.v4[0], port, emit))\n" +
			"\t\tbuf = append(buf, ipsetmember.MakeIPPortProtoV6(d.v6[0], port, emit))",
	},
}

var portsAxes = []portsAxis{
	{
		Name:                     "Ports0",
		Len:                      0,
		Fields:                   "",
		EqualToBody:              "",
		Init:                     "",
		AppendIPPortPortLoopBody: "\t// No ports.",
	},
	{
		Name:        "Ports1",
		Len:         1,
		Fields:      "\tports [1]portHandle\n",
		EqualToBody: "\tif d.ports != o.ports {\n\t\treturn false\n\t}",
		Init:        "ports: [1]portHandle{internEndpointPort(ports[0])},",
		AppendIPPortPortLoopBody: "\tif port, emit, ok := portHandleMatches(d.ports[0], name, proto); ok {\n" +
			"__PER_PORT_BODY__\n" +
			"\t}",
	},
	{
		Name:        "Ports2",
		Len:         2,
		Fields:      "\tports [2]portHandle\n",
		EqualToBody: "\tif d.ports != o.ports {\n\t\treturn false\n\t}",
		Init:        "ports: [2]portHandle{internEndpointPort(ports[0]), internEndpointPort(ports[1])},",
		AppendIPPortPortLoopBody: "\tfor _, h := range d.ports {\n" +
			"\t\tif port, emit, ok := portHandleMatches(h, name, proto); ok {\n" +
			"__PER_PORT_BODY__\n" +
			"\t\t}\n" +
			"\t}",
	},
}

var parentsAxes = []parentsAxis{
	{
		Name:                "Parents0",
		Len:                 0,
		Fields:              "",
		EachParentBody:      "\t// No parents.",
		HasParentBody:       "\treturn false",
		EqualToBody:         "",
		Init:                "",
		GetHandleParentScan: "",
	},
	{
		Name:   "Parents1",
		Len:    1,
		Fields: "\tparents [1]*npParentData\n",
		EachParentBody: "\tif !yield(d.parents[0]) {\n" +
			"\t\treturn\n" +
			"\t}",
		HasParentBody: "\treturn d.parents[0] == parent",
		EqualToBody:   "\tif d.parents != o.parents {\n\t\treturn false\n\t}",
		Init:          "parents: [1]*npParentData{parents[0]},",
		GetHandleParentScan: "\tif h, ok := d.parents[0].labels.GetHandle(name); ok {\n" +
			"\t\treturn h, true\n" +
			"\t}",
	},
	{
		Name:   "Parents2",
		Len:    2,
		Fields: "\tparents [2]*npParentData\n",
		EachParentBody: "\tfor _, p := range d.parents {\n" +
			"\t\tif !yield(p) {\n" +
			"\t\t\treturn\n" +
			"\t\t}\n" +
			"\t}",
		HasParentBody: "\treturn d.parents[0] == parent || d.parents[1] == parent",
		EqualToBody:   "\tif d.parents != o.parents {\n\t\treturn false\n\t}",
		Init:          "parents: [2]*npParentData{parents[0], parents[1]},",
		GetHandleParentScan: "\tif h, ok := d.parents[0].labels.GetHandle(name); ok {\n" +
			"\t\treturn h, true\n" +
			"\t}\n" +
			"\tif h, ok := d.parents[1].labels.GetHandle(name); ok {\n" +
			"\t\treturn h, true\n" +
			"\t}",
	},
}

const header = `// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Code generated by felix/labelindex/gen/endpointdata; DO NOT EDIT.

package labelindex

import (
	"iter"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/labelindex/ipsetmember"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)
`

const variantTmpl = `
// {{.TypeName}} is the counted variant for {{.CIDR.Name}}, {{.Ports.Name}}, {{.Parents.Name}}.
type {{.TypeName}} struct {
	labels uniquelabels.Map
{{.CIDR.Fields}}{{.Ports.Fields}}{{.Parents.Fields}}	cache set.Adaptive[string]
}

// GetHandle is inlined per-variant so the hot selector-eval path
// doesn't allocate the iter.Seq closure that a generic walker would.
func (d *{{.TypeName}}) GetHandle(name uniquestr.Handle) (uniquestr.Handle, bool) {
	if h, ok := d.labels.GetHandle(name); ok {
		return h, true
	}
{{.Parents.GetHandleParentScan}}
	return uniquestr.Handle{}, false
}

func (d *{{.TypeName}}) OwnLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return d.labels.AllHandles()
}

func (d *{{.TypeName}}) AllOwnAndParentLabelHandles() iter.Seq2[uniquestr.Handle, uniquestr.Handle] {
	return allOwnAndParentLabelHandles(d.labels, d.EachParent)
}

func (d *{{.TypeName}}) AppendCIDROrIPMembers(buf []ipsetmember.IPSetMember) []ipsetmember.IPSetMember {
{{.CIDR.AppendCIDROrIPBody}}
	return buf
}

func (d *{{.TypeName}}) AppendIPPortMembers(buf []ipsetmember.IPSetMember,
	name string, proto ipsetmember.Protocol) []ipsetmember.IPSetMember {
{{.AppendIPPortBody}}
	return buf
}

func (d *{{.TypeName}}) EachParent(yield func(*npParentData) bool) {
{{.Parents.EachParentBody}}
}

func (d *{{.TypeName}}) HasParent(parent *npParentData) bool {
{{.Parents.HasParentBody}}
}

func (d *{{.TypeName}}) AddMatchingIPSetID(id string)       { d.cache.Add(id) }
func (d *{{.TypeName}}) RemoveMatchingIPSetID(id string)    { d.cache.Discard(id) }
func (d *{{.TypeName}}) NumMatchingIPSetIDs() int           { return d.cache.Len() }
func (d *{{.TypeName}}) MatchingIPSetIDs() iter.Seq[string] { return d.cache.All() }
func (d *{{.TypeName}}) ClearMatchingIPSetIDs()             { d.cache.Clear() }
func (d *{{.TypeName}}) MatchingIPSetIDsString() string     { return d.cache.String() }

func (d *{{.TypeName}}) EqualTo(other endpointData) bool {
	o, ok := other.(*{{.TypeName}})
	if !ok {
		return false
	}
	if !d.labels.Equals(o.labels) {
		return false
	}
{{.CIDR.EqualToBody}}
{{.Ports.EqualToBody}}
{{.Parents.EqualToBody}}
	return true
}
`

func typeName(c cidrAxis, p portsAxis, n parentsAxis) string {
	return "ep" + c.Name + p.Name + n.Name
}

func mustExec(t *template.Template, data any) string {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		log.Fatalf("template execute: %v", err)
	}
	return buf.String()
}

func main() {
	out := bytes.NewBufferString(header)
	vt := template.Must(template.New("variant").Parse(variantTmpl))

	for _, c := range cidrAxes {
		for _, p := range portsAxes {
			// Compose the variant-specific AppendIPPortMembers body
			// from the ports-axis port-loop template + the cidr-axis
			// per-port emit body. For Ports0 the body has no
			// __PER_PORT_BODY__ marker, so the replace is a no-op.
			appendIPPortBody := strings.ReplaceAll(
				p.AppendIPPortPortLoopBody,
				"__PER_PORT_BODY__",
				c.AppendIPPortPerPortBody,
			)
			for _, n := range parentsAxes {
				out.WriteString(mustExec(vt, struct {
					TypeName         string
					CIDR             cidrAxis
					Ports            portsAxis
					Parents          parentsAxis
					AppendIPPortBody string
				}{
					TypeName:         typeName(c, p, n),
					CIDR:             c,
					Ports:            p,
					Parents:          n,
					AppendIPPortBody: appendIPPortBody,
				}))
			}
		}
	}

	// Dispatcher: single function with nested switches.
	out.WriteString("\nfunc newCountedEndpointData(\n")
	out.WriteString("\tlabels uniquelabels.Map,\n")
	out.WriteString("\tshape cidrShape,\n")
	out.WriteString("\tv4 ip.V4Addr,\n")
	out.WriteString("\tv6 ip.V6Addr,\n")
	out.WriteString("\tports []model.EndpointPort,\n")
	out.WriteString("\tparents []*npParentData,\n")
	out.WriteString(") endpointData {\n")
	out.WriteString("\tswitch shape {\n")
	for _, c := range cidrAxes {
		fmt.Fprintf(out, "\tcase cidrShape%s:\n", c.Name)
		out.WriteString("\t\tswitch len(ports) {\n")
		for _, p := range portsAxes {
			fmt.Fprintf(out, "\t\tcase %d:\n", p.Len)
			out.WriteString("\t\t\tswitch len(parents) {\n")
			for _, n := range parentsAxes {
				fmt.Fprintf(out, "\t\t\tcase %d:\n", n.Len)
				fmt.Fprintf(out, "\t\t\t\treturn &%s{\n", typeName(c, p, n))
				out.WriteString("\t\t\t\t\tlabels: labels,\n")
				if c.Init != "" {
					fmt.Fprintf(out, "\t\t\t\t\t%s\n", c.Init)
				}
				if p.Init != "" {
					fmt.Fprintf(out, "\t\t\t\t\t%s\n", p.Init)
				}
				if n.Init != "" {
					fmt.Fprintf(out, "\t\t\t\t\t%s\n", n.Init)
				}
				out.WriteString("\t\t\t\t}\n")
			}
			out.WriteString("\t\t\t}\n")
		}
		out.WriteString("\t\t}\n")
	}
	out.WriteString("\t}\n")
	out.WriteString("\tpanic(\"newCountedEndpointData: unhandled shape; newEndpointData should have routed to general\")\n")
	out.WriteString("}\n")

	formatted, err := format.Source(out.Bytes())
	if err != nil {
		os.Stderr.WriteString(out.String())
		log.Fatalf("gofmt: %v", err)
	}

	// Resolve output path so the generator works when invoked from
	// either the repo root (`go run ./felix/labelindex/gen/endpointdata/main.go`)
	// or via `go generate ./felix/labelindex/...` (which runs from the
	// labelindex package dir).
	outPath := "felix/labelindex/endpoint_data_impls_gen.go"
	if _, err := os.Stat("endpoint_data.go"); err == nil {
		outPath = "endpoint_data_impls_gen.go"
	}
	if err := os.WriteFile(outPath, formatted, 0o644); err != nil {
		log.Fatalf("write: %v", err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outPath, len(formatted))
}
