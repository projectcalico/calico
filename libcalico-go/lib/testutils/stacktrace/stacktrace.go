package stacktrace

import (
	"fmt"
	"runtime"
	"strings"
)

// MiniStackStrace returns a short stack trace showing the first couple of callers
// that don't contain any element of filesToSkip in their file names.
func MiniStackStrace(filesToSkip ...string) string {
	// Find the first/second caller outside this package.
callerLoop:
	for i := 2; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			return "unknown:0"
		}
		if strings.Contains(file, "/stacktrace/") {
			continue
		}
		for _, pkg := range filesToSkip {
			if strings.Contains(file, pkg) {
				continue callerLoop
			}
		}
		parts := strings.Split(file, "/")
		file = parts[len(parts)-1]
		firstCaller := fmt.Sprintf("%s:%d", file, line)

		_, file, line, ok = runtime.Caller(i + 1)
		if !ok || !strings.Contains(file, "/calico/") {
			return firstCaller
		} else {
			parts := strings.Split(file, "/")
			file = parts[len(parts)-1]
			return fmt.Sprintf("%s:%d>%s", file, line, firstCaller)
		}
	}
}
