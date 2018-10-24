package startup

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Default interfaces to exclude for any logic following the first-found
// auto detect IP method
var DEFAULT_INTERFACES_TO_EXCLUDE []string = []string{
	"docker.*", "cbr.*", "dummy.*",
	"virbr.*", "lxcbr.*", "veth.*", "lo",
	"cali.*", "tunl.*", "flannel.*", "kube-ipvs.*",
}

const defaultNodenameFile = "/var/lib/calico/nodename"

// Checks that the filesystem is as expected and fix it if possible
func ensureFilesystemAsExpected() {
	// BIRD requires the /var/run/calico directory in order to provide status
	// information over the control socket, but other backends do not
	// need this check.
	if strings.ToLower(os.Getenv("CALICO_NETWORKING_BACKEND")) == "bird" {
		runDir := "/var/run/calico"
		// Check if directory already exists
		if _, err := os.Stat(runDir); err != nil {
			// Create the runDir
			if err = os.MkdirAll(runDir, os.ModeDir); err != nil {
				log.Errorf("Unable to create '%s'", runDir)
				terminate()
			}
			log.Warnf("Expected %s to be mounted into the container but it wasn't present. 'calicoctl node status' may provide incomplete status information", runDir)
		}
	}

	// Make sure the /var/lib/calico directory exists.
	libDir := "/var/lib/calico"
	// Check if directory already exists
	if _, err := os.Stat(libDir); err != nil {
		// Create the libDir
		if err = os.MkdirAll(libDir, os.ModeDir); err != nil {
			log.Errorf("Unable to create '%s'", libDir)
			terminate()
		}
		log.Warnf("Expected %s to be mounted into the container but it wasn't present. Node name may not be detected properly", libDir)
	}

	// Ensure the log directory exists but only if logging to file is enabled.
	if strings.ToLower(os.Getenv("CALICO_DISABLE_FILE_LOGGING")) != "true" {
		logDir := "/var/log/calico"
		// Check if directory already exists
		if _, err := os.Stat(logDir); err != nil {
			// Create the logDir
			if err = os.MkdirAll(logDir, os.ModeDir); err != nil {
				log.Errorf("Unable to create '%s'", logDir)
				terminate()
			}
			log.Warnf("Expected %s to be mounted into the container but it wasn't present. 'calicoctl node diags' will not be able to collect calico/node logs", logDir)
		}
	}
}

// ipv6Supported returns true if IPv6 is supported on this platform.  This performs
// a check on the appropriate Felix parameter and if supported also performs a
// simplistic check of /proc/sys/net/ipv6 (since platforms that do not have IPv6
// compiled in will not have this entry).
func ipv6Supported() bool {
	// First check if Felix param is false
	IPv6isSupported := evaluateENVBool("FELIX_IPV6SUPPORT", true)
	if !IPv6isSupported {
		return false
	}

	// If supported, then also check /proc/sys/net/ipv6.
	_, err := os.Stat("/proc/sys/net/ipv6")
	supported := (err == nil)
	log.Infof("IPv6 supported on this platform: %v", supported)
	return supported
}
