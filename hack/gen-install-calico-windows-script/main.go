// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"text/template"
)

type install struct {
	Product     string `json:"product"`
	ProductName string `json:"productName"`
	Version     string `json:"version"`
	BaseUrl     string `json:"baseUrl"`
	RootDir     string `json:"rootDir"`
	ZipFileName string `json:"zipFileName"`
}

var installs = map[string]install{
	"Calico": {
		Product:     "Calico",
		ProductName: "Calico for Windows",
		RootDir:     "CalicoWindows",
		ZipFileName: "calico-windows.zip",
	},
	"Calico Enterprise": {
		Product:     "Calico Enterprise",
		ProductName: "Tigera Calico for Windows",
		RootDir:     "TigeraCalico",
		ZipFileName: "tigera-calico-windows.zip",
	},
}

func newInstall(product, version, baseUrl string) (install, error) {
	var data install

	if install, ok := installs[product]; ok {
		data = install
		data.Version = version
		data.BaseUrl = baseUrl
		return data, nil
	}
	return data, fmt.Errorf("invalid product: %v", product)
}

var (
	product      string
	version      string
	templatePath string
	baseUrl      string
)

// This program generates the Calico for Windows installation script for a given product, version and baseUrl.
//
// Examples:
//
// For Calico v3.21.1:
//
// gen-install-calico-windows-script \
//    -product Calico \
//    -version v3.21.1 \
//    -templatePath windows-packaging/install-calico-windows.ps1.tpl \
//    -baseUrl https://docs.projectcalico.org > install-calico-windows.ps1
//
//
// For Calico Enterprise v3.11.0:
//
// gen-install-calico-windows-script \
//    -product "Calico Enterprise" \
//    -version v3.11.0 \
//    -templatePath windows-packaging/install-calico-windows.ps1.tpl \
//    -baseUrl https://docs.tigera.io > install-calico-windows.ps1
func main() {
	flag.StringVar(&product, "product", "", `product to generate install script for. either "Calico" or "Calico Enterprise"`)
	flag.StringVar(&version, "version", "", `version`)
	flag.StringVar(&templatePath, "templatePath", "", `path to the template for the installation script`)
	flag.StringVar(&baseUrl, "baseUrl", "", `URL where the installation zip file will be hosted. Required for Calico only`)
	flag.Parse()

	log.Printf("product: %v, version: %v, templatePath: %v, baseUrl: %v", product, version, templatePath, baseUrl)

	if product == "" || version == "" || templatePath == "" {
		log.Fatalf("product, version, templatePath, and baseUrl must all be specified")
	}

	if product == "Calico" && baseUrl == "" {
		log.Fatalf("baseUrl is required for Calico")
	}

	if _, err := os.Stat(templatePath); errors.Is(err, os.ErrNotExist) {
		log.Fatalf("templatePath %v does not exist", templatePath)
	}

	data, err := newInstall(product, version, baseUrl)
	if err != nil {
		log.Fatalf("error generating installation script data: %v", err)
	}

	log.Printf("using install data: %+v", data)

	t, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("error parsing template: %v", err)
	}

	err = t.Execute(os.Stdout, data)
	if err != nil {
		log.Fatalf("error rendering template: %v", err)
	}
}
