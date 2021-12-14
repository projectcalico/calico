// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package argutils

// ArgStringOrBlank returns the requested argument as a string, or as a blank
// string if the argument is not present.
func ArgStringOrBlank(args map[string]interface{}, argName string) string {
	if args[argName] != nil {
		return args[argName].(string)
	}
	return ""
}

// ArgStringsOrBlank returns the requested argument as a []string, or as a
// []string{""} if the argument is not present.
func ArgStringsOrBlank(args map[string]interface{}, argName string) []string {
	val := args[argName].([]string)
	if len(val) > 0 {
		return val
	}
	return []string{""}
}

// ArgBoolOrFalse returns the requested argument as a boolean, or as false
// if the argument is not present.
func ArgBoolOrFalse(args map[string]interface{}, argName string) bool {
	if args[argName] != nil {
		return args[argName].(bool)
	}
	return false
}
