package cmdwrapper

func isSIGCHLD(s os.Signal) bool {
	return s == syscall.SIGCHLD
}
