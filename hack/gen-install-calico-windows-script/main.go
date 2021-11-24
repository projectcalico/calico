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

func newInstall(product, version, baseUrl string) (install, error) {
	data := install{
		Product: product,
		Version: version,
		BaseUrl: baseUrl,
	}
	var productName, rootDir, zipFileName string

	if product == "Calico" {
		productName = "Calico for Windows"
		rootDir = "CalicoWindows"
		zipFileName = "calico-windows.zip"
	} else if product == "Calico Enterprise" {
		productName = "Tigera Calico for Windows"
		rootDir = "TigeraCalico"
		zipFileName = "tigera-calico-windows.zip"
	} else {
		return data, fmt.Errorf("invalid product: %v", product)
	}

	data.ProductName = productName
	data.RootDir = rootDir
	data.ZipFileName = zipFileName
	return data, nil
}

var (
	product      string
	version      string
	templatePath string
	baseUrl      string
	debug        bool
)

func main() {
	flag.StringVar(&product, "product", "", `product to generate install script for. either "Calico" or "Calico Enterprise"`)
	flag.StringVar(&version, "version", "", `version`)
	flag.StringVar(&templatePath, "templatePath", "", `path to the template for the installation script`)
	flag.StringVar(&baseUrl, "baseUrl", "", `URL where the installation zip file will be hosted. Required for Calico only`)
	flag.BoolVar(&debug, "debug", false, `enable debug logging`)
	flag.Parse()

	if debug {
		log.Printf("product: %v, version: %v, templatePath: %v, baseUrl: %v", product, version, templatePath, baseUrl)
	}

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

	if debug {
		log.Printf("using install data: %+v", data)
	}

	t, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatalf("error parsing template: %v", err)
	}

	err = t.Execute(os.Stdout, data)
	if err != nil {
		log.Fatalf("error rendering template: %v", err)
	}
}
