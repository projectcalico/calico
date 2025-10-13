package cmdwrapper

import (
	"os"
	"syscall"
)

func isSIGCHLD(s os.Signal) bool {
	return s == syscall.SIGCHLD
}
