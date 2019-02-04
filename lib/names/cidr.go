package names

import (
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/sirupsen/logrus"
	"strings"
)

// CIDRToName converts a CIDR to a valid resource name.
func CIDRToName(cidr net.IPNet) string {
	name := strings.Replace(cidr.String(), ".", "-", 3)
	name = strings.Replace(name, ":", "-", 7)
	name = strings.Replace(name, "/", "-", 1)

	logrus.WithFields(logrus.Fields{
		"Name":  name,
		"IPNet": cidr.String(),
	}).Debug("Converted IPNet to resource name")

	return name
}
