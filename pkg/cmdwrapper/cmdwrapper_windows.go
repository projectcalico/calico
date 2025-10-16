package cmdwrapper

import "os"

func isSIGCHLD(s os.Signal) bool {
	return false // Doesn't exist on Windows.
}
