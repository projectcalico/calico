// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package config

import (
	"io/ioutil"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/go-ini/ini"
)

func LoadConfigFile(filename string) (map[string]string, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Infof("Ignoring absent config file: %v", filename)
		return nil, nil
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return LoadConfigFileData(data)
}

func LoadConfigFileData(data []byte) (map[string]string, error) {
	iniFile, err := ini.Load(data)
	if err != nil {
		log.Errorf("Failed to load config file: %v", err)
		return nil, err
	}
	kvs := make(map[string]string)
	for _, section := range iniFile.Sections() {
		log.Debugf("Parsing section %v", section.Name())
		for _, key := range section.Keys() {
			if _, ok := kvs[key.Name()]; ok {
				log.Warningf("Multiple values defined for key %v", key.Name())
			}
			kvs[key.Name()] = key.Value()
		}
	}
	return kvs, nil
}
