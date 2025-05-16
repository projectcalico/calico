// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
package assert

import (
	"bufio"
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

var failImmediately bool

func SetFailImmediately(fail bool) {
	failImmediately = fail
}

func Equal[T comparable](t *testing.T, expected, actual T, msgAndArgs ...interface{}) bool {
	t.Helper()
	if expected != actual {
		return Fail(t, fmt.Sprintf("Expected %v to equal %v", expected, actual), msgAndArgs...)
	}
	return false
}

type AnyStruct interface {
	*struct{} | struct{}
}

func ObjectsEqual[T any](t *testing.T, expected, actual T, msgAndArgs ...interface{}) bool {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		return Fail(t, fmt.Sprintf("Expected %v to equal %v", expected, actual), msgAndArgs...)
	}
	return false
}

func NoError(t *testing.T, err error, msgAndArgs ...interface{}) bool {
	t.Helper()
	if err != nil {
		return Fail(t, fmt.Sprintf("Expected no error, got %v", err), msgAndArgs...)
	}
	return false
}

func Nil[T any](t *testing.T, v *T, msgAndArgs ...interface{}) bool {
	t.Helper()
	var zero *T
	if v != zero {
		return Fail(t, "Expected value to be nil", msgAndArgs...)
	}
	return true
}

func NotNil[T any](t *testing.T, v *T, msgAndArgs ...interface{}) bool {
	t.Helper()
	var zero *T
	if v == zero {
		return Fail(t, "Expected value to not be nil", msgAndArgs...)
	}
	return true
}

func ErrorIs(t *testing.T, expectedErr error, err error, msgAndArgs ...interface{}) bool {
	t.Helper()
	if err == nil {
		return Fail(t, "Expected error, got none", msgAndArgs...)
	}
	return false
}

func Panic(t *testing.T, f func(), msgAndArgs ...interface{}) bool {
	t.Helper()
	var panicked bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		f()
	}()
	if !panicked {
		return Fail(t, "Expected panic, got none", msgAndArgs...)
	}
	return true
}

func ContainsKey[K comparable, V any](t *testing.T, m map[K]V, expectedKey K, msgAndArgs ...interface{}) bool {
	t.Helper()
	if _, ok := m[expectedKey]; !ok {
		return Fail(t, fmt.Sprintf("Expected map to contain key %v", expectedKey), msgAndArgs...)
	}
	return false
}

func ContainsSubstring(t *testing.T, expectedSubstring, str string, msgAndArgs ...interface{}) bool {
	t.Helper()
	if !strings.Contains(str, expectedSubstring) {
		return Fail(t, fmt.Sprintf("Expected %s to contain substring %s", str, expectedSubstring), msgAndArgs...)
	}
	return false
}

func NotContainKey[K comparable, V any](t *testing.T, m map[K]V, expectedKey K, msgAndArgs ...interface{}) bool {
	t.Helper()
	if _, ok := m[expectedKey]; ok {
		return Fail(t, fmt.Sprintf("Expected map to not contain key %v", expectedKey), msgAndArgs...)
	}
	return false
}

func ContainsKeyWithComparable[K comparable, V comparable](t *testing.T, m map[K]V, expectedKey K, expectedValue V, msgAndArgs ...interface{}) bool {
	t.Helper()
	if !ContainsKey(t, m, expectedKey, msgAndArgs...) {
		return false
	} else if m[expectedKey] != expectedValue {
		return Fail(t, fmt.Sprintf("Expected map[%v] to be %v, got %v", expectedKey, expectedValue, m[expectedKey]), msgAndArgs...)
	}
	return true
}

// Fail reports a failure through
func Fail(t *testing.T, failureMessage string, msgAndArgs ...interface{}) bool {
	t.Helper()
	content := []labeledContent{
		{"Error Trace", strings.Join(CallerInfo(), "\n\t\t\t")},
		{"Error", failureMessage},
		{"Test", t.Name()},
	}

	message := messageFromMsgAndArgs(msgAndArgs...)
	if len(message) > 0 {
		content = append(content, labeledContent{"Messages", message})
	}

	t.Errorf("\n%s", ""+labeledOutput(content...))

	if failImmediately {
		t.FailNow()
	}

	return false
}

func messageFromMsgAndArgs(msgAndArgs ...interface{}) string {
	if len(msgAndArgs) == 0 || msgAndArgs == nil {
		return ""
	}
	if len(msgAndArgs) == 1 {
		msg := msgAndArgs[0]
		if msgAsStr, ok := msg.(string); ok {
			return msgAsStr
		}
		return fmt.Sprintf("%+v", msg)
	}
	if len(msgAndArgs) > 1 {
		return fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)
	}
	return ""
}

type labeledContent struct {
	label   string
	content string
}

// labeledOutput returns a string consisting of the provided labeledContent. Each labeled output is appended in the following manner:
//
//	\t{{label}}:{{align_spaces}}\t{{content}}\n
//
// The initial carriage return is required to undo/erase any padding added by testing.T.Errorf. The "\t{{label}}:" is for the label.
// If a label is shorter than the longest label provided, padding spaces are added to make all the labels match in length. Once this
// alignment is achieved, "\t{{content}}\n" is added for the output.
//
// If the content of the labeledOutput contains line breaks, the subsequent lines are aligned so that they start at the same location as the first line.
func labeledOutput(content ...labeledContent) string {
	longestLabel := 0
	for _, v := range content {
		if len(v.label) > longestLabel {
			longestLabel = len(v.label)
		}
	}
	var output string
	for _, v := range content {
		output += "\t" + v.label + ":" + strings.Repeat(" ", longestLabel-len(v.label)) + "\t" + indentMessageLines(v.content, longestLabel) + "\n"
	}
	return output
}

// Aligns the provided message so that all lines after the first line start at the same location as the first line.
// Assumes that the first line starts at the correct location (after carriage return, tab, label, spacer and tab).
// The longestLabelLen parameter specifies the length of the longest label in the output (required because this is the
// basis on which the alignment occurs).
func indentMessageLines(message string, longestLabelLen int) string {
	outBuf := new(bytes.Buffer)

	for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
		// no need to align first line because it starts at the correct location (after the label)
		if i != 0 {
			// append alignLen+1 spaces to align with "{{longestLabel}}:" before adding tab
			outBuf.WriteString("\n\t" + strings.Repeat(" ", longestLabelLen+1) + "\t")
		}
		outBuf.WriteString(scanner.Text())
	}

	return outBuf.String()
}

// CallerInfo returns an array of strings containing the file and line number
// of each stack frame leading from the current test to the assert call that
// failed.
func CallerInfo() []string {

	var pc uintptr
	var ok bool
	var file string
	var line int
	var name string

	callers := []string{}
	for i := 0; ; i++ {
		pc, file, line, ok = runtime.Caller(i)
		if !ok {
			// The breaks below failed to terminate the loop, and we ran off the
			// end of the call stack.
			break
		}

		// This is a huge edge case, but it will panic if this is the case, see #180
		if file == "<autogenerated>" {
			break
		}

		f := runtime.FuncForPC(pc)
		if f == nil {
			break
		}
		name = f.Name()

		// testing.tRunner is the standard library function that calls
		// tests. Subtests are called directly by tRunner, without going through
		// the Test/Benchmark/Example function that contains the t.Run calls, so
		// with subtests we should break when we hit tRunner, without adding it
		// to the list of callers.
		if name == "testing.tRunner" {
			break
		}

		parts := strings.Split(file, "/")
		if len(parts) > 1 {
			filename := parts[len(parts)-1]
			dir := parts[len(parts)-2]
			if (dir != "assert" && dir != "mock" && dir != "require") || filename == "mock_test.go" {
				callers = append(callers, fmt.Sprintf("%s:%d", file, line))
			}
		}

		// Drop the package
		segments := strings.Split(name, ".")
		name = segments[len(segments)-1]
		if isTest(name, "Test") ||
			isTest(name, "Benchmark") ||
			isTest(name, "Example") {
			break
		}
	}

	return callers
}

// Stolen from the `go test` tool.
// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(r)
}
