// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package main

import (
	"fmt"
	"os"
	"regexp"
)

func main() {
	pwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fmt.Println("PWD:", pwd)

	// Read the protobuf file.
	protoFile, err := os.ReadFile("./felixbackend.pb.go")
	if err != nil {
		panic(err)
	}

	// Find the messages in the protobuf file.
	re := regexp.MustCompile(`RegisterType\(\(\*(\w+)\)\(nil\)`)
	var messageNames []string
	for _, m := range re.FindAllSubmatch(protoFile, -1) {
		messageNames = append(messageNames, string(m[1]))
	}

	// Generate the output file.
	output := `// Code generated by genlogmethods.go. DO NOT EDIT.

package proto

import (
	"io"

	"github.com/gogo/protobuf/proto"
)

`
	for _, name := range messageNames {
		output += fmt.Sprintf("func (m *%s) WriteForLog(w io.Writer) (err error) {\n"+
			"\treturn proto.CompactText(w, m)\n"+
			"}\n\n", name)
	}

	err = os.WriteFile("./zz_generated.logmethods.go", []byte(output), 0644)
	if err != nil {
		panic(err)
	}
}
