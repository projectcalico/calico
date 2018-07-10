// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"
	"text/template"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calicoctl/calicoctl/resourcemgr"
	"github.com/projectcalico/go-json/json"
	"github.com/projectcalico/go-yaml-wrapper"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

type resourcePrinter interface {
	print(client client.Interface, resources []runtime.Object) error
}

// resourcePrinterJSON implements the resourcePrinter interface and is used to display
// a slice of resources in JSON format.
type resourcePrinterJSON struct{}

func (r resourcePrinterJSON) print(client client.Interface, resources []runtime.Object) error {
	// If the results contain a single entry then extract the only value.
	var rs interface{}
	if len(resources) == 1 {
		rs = resources[0]
	} else {
		rs = resources
	}
	if output, err := json.MarshalIndent(rs, "", "  "); err != nil {
		return err
	} else {
		fmt.Printf("%s\n", string(output))
	}
	return nil
}

// resourcePrinterYAML implements the resourcePrinter interface and is used to display
// a slice of resources in YAML format.
type resourcePrinterYAML struct{}

func (r resourcePrinterYAML) print(client client.Interface, resources []runtime.Object) error {
	// If the results contain a single entry then extract the only value.
	var rs interface{}
	if len(resources) == 1 {
		rs = resources[0]
	} else {
		rs = resources
	}
	if output, err := yaml.Marshal(rs); err != nil {
		return err
	} else {
		fmt.Printf("%s", string(output))
	}
	return nil
}

// resourcePrinterTable implements the resourcePrinter interface and is used to display
// a slice of resources in ps table format.
type resourcePrinterTable struct {
	// The headings to display in the table.  If this is nil, the default headings for the
	// resource are used instead (in which case the `wide` boolean below is used to specify
	// whether wide or narrow format is required.
	headings []string

	// Wide format.  When headings have not been explicitly specified, this is used to
	// determine whether to the resource-specific default wide or narrow headings.
	wide bool

	// Namespace included. When a resource being printed is namespaced, this is used
	// to determine if the namespace column should be printed or not.
	printNamespace bool
}

func (r resourcePrinterTable) print(client client.Interface, resources []runtime.Object) error {
	log.Infof("Output in table format (wide=%v)", r.wide)
	for _, resource := range resources {
		// Get the resource manager for the resource type.
		rm := resourcemgr.GetResourceManager(resource)

		// If no headings have been specified then we must be using the default
		// headings for that resource type.
		headings := r.headings
		if r.headings == nil {
			headings = rm.GetTableDefaultHeadings(r.wide)
		}

		// Look up the template string for the specific resource type.
		tpls, err := rm.GetTableTemplate(headings, r.printNamespace)
		if err != nil {
			return err
		}

		// Convert the template string into a template - we need to include the join
		// function.
		fns := template.FuncMap{
			"join":   join,
			"config": config(client),
		}
		tmpl, err := template.New("get").Funcs(fns).Parse(tpls)
		if err != nil {
			panic(err)
		}

		// Use a tabwriter to write out the teplate - this provides better formatting.
		writer := tabwriter.NewWriter(os.Stdout, 5, 1, 3, ' ', 0)
		err = tmpl.Execute(writer, resource)
		if err != nil {
			panic(err)
		}
		writer.Flush()

		// Templates for ps format are internally defined and therefore we should not
		// hit errors writing the table formats.
		if err != nil {
			panic(err)
		}

		// Leave a gap after each table.
		fmt.Printf("\n")
	}
	return nil
}

// resourcePrinterTemplateFile implements the resourcePrinter interface and is used to display
// a slice of resources using a user-defined go-lang template specified in a file.
type resourcePrinterTemplateFile struct {
	templateFile string
}

func (r resourcePrinterTemplateFile) print(client client.Interface, resources []runtime.Object) error {
	template, err := ioutil.ReadFile(r.templateFile)
	if err != nil {
		return err
	}
	rp := resourcePrinterTemplate{template: string(template)}
	return rp.print(client, resources)
}

// resourcePrinterTemplate implements the resourcePrinter interface and is used to display
// a slice of resources using a user-defined go-lang template string.
type resourcePrinterTemplate struct {
	template string
}

func (r resourcePrinterTemplate) print(client client.Interface, resources []runtime.Object) error {
	// We include a join function in the template as it's useful for multi
	// value columns.
	fns := template.FuncMap{
		"join":   join,
		"config": config(client),
	}
	tmpl, err := template.New("get").Funcs(fns).Parse(r.template)
	if err != nil {
		return err
	}

	err = tmpl.Execute(os.Stdout, resources)
	return err
}

// join is similar to strings.Join() but takes an arbitrary slice of interfaces and converts
// each to its string representation and joins them together with the provided separator
// string.
func join(items interface{}, separator string) string {
	// If this is a slice of strings - just use the strings.Join function.
	switch s := items.(type) {
	case []string:
		return strings.Join(s, separator)
	}

	// Otherwise, provided this is a slice, just convert each item to a string and
	// join together.
	switch reflect.TypeOf(items).Kind() {
	case reflect.Slice:
		slice := reflect.ValueOf(items)
		buf := new(bytes.Buffer)
		for i := 0; i < slice.Len(); i++ {
			if i > 0 {
				buf.WriteString(separator)
			}
			fmt.Fprint(buf, slice.Index(i).Interface())
		}
		return buf.String()
	}

	// The supplied items is not a slice - so just convert to a string.
	return fmt.Sprint(items)
}

// config returns a function that returns the current global named config
// value.
func config(client client.Interface) func(string) string {
	var asValue string
	return func(name string) string {
		switch strings.ToLower(name) {
		case "asnumber":
			if asValue == "" {
				if bgpConfig, err := client.BGPConfigurations().Get(context.Background(), "default", options.GetOptions{}); err != nil {
					asValue = "unknown"
				} else {
					asValue = bgpConfig.Spec.ASNumber.String()
				}
			}
			return asValue
		}
		panic("unhandled config type")
	}
}
