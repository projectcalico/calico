package netlink

import (
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

func IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "operation not supported")
}

func IsExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsExist(err) || strings.Contains(err.Error(), "already exists")
}

func IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return true
	}
	return strings.Contains(err.Error(), "not found")
}
