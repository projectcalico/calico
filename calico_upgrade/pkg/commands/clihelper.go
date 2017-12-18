// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"strings"
)

const (
	lineLength = 79
	sepChar    = '-'
	bullet     = " * "
)

// cliHelper contains common methods for writing/reading from the CLI.
// It also implements the StatusWriterInterface, so may be used directly by the
// migration handler for writing status information.
type cliHelper struct {
}

// Display a 79-char word wrapped status message.
func (m *cliHelper) Msg(msg string) {
	lines := wordWrap(msg, lineLength)
	for _, line := range lines {
		fmt.Println(line)
	}
}

// Display a 79-char word wrapped sub status (a bulleted message).
func (m *cliHelper) Bullet(msg string) {
	lines := wordWrap(msg, lineLength-len(bullet))
	fmt.Println(bullet + lines[0])
	for _, line := range lines[1:] {
		fmt.Println("   " + line)
	}
}

// Display a 79-char word wrapped error message.
func (m *cliHelper) Error(msg string) {
	lines := wordWrap("ERROR: "+msg, lineLength)
	for _, line := range lines {
		fmt.Println(line)
	}
}

// Display a 79-char word wrapped error message.
func (m *cliHelper) NewLine() {
	fmt.Println("")
}

// Display a 79-char word wrapped error message.
func (m *cliHelper) Separator() {
	sep := make([]byte, lineLength)
	for i := 0; i < lineLength; i++ {
		sep[i] = sepChar
	}
	m.NewLine()
	fmt.Println(string(sep))
	m.NewLine()
}

// Display a generic proceed? message and wait for a "yes" response.
func (m *cliHelper) ConfirmProceed() {
	fmt.Print("Type \"yes\" to proceed (any other input cancels): ")
	var input string
	fmt.Scanln(&input)
	if strings.ToLower(strings.TrimSpace(input)) != "yes" {
		fmt.Println("User cancelled. Exiting.")
		os.Exit(1)
	}
}

// wordWrap wraps a long string at the specified max length. The text may
// contain newlines.
func wordWrap(text string, length int) []string {
	// First split by newlines. We want to honor existing newlines.
	var lines []string
	parts := strings.Split(text, "\n")
	for _, part := range parts {
		lines = append(lines, wordWrapPart(part, length)...)
	}
	return lines
}

// wordWrapPart wraps a long string at the specified max length. Newlines
// are treated as whitespace.
func wordWrapPart(text string, length int) []string {
	// First split by newlines. We want to honor existing newlines.
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{}
	}

	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > length {
			lines = append(lines, line)
			line = word
		} else {
			line += " " + word
		}
	}
	lines = append(lines, line)

	return lines
}
