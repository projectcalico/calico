package environment

type Features struct {
	// SNATFullyRandom is true if --random-fully is supported by the SNAT action.
	SNATFullyRandom bool
	// MASQFullyRandom is true if --random-fully is supported by the MASQUERADE action.
	MASQFullyRandom bool
	// RestoreSupportsLock is true if the iptables-restore command supports taking the xtables lock and the
	// associated -w and -W arguments.
	RestoreSupportsLock bool
	// ChecksumOffloadBroken is true for kernels that have broken checksum offload for packets with SNATted source
	// ports. See https://github.com/projectcalico/calico/issues/3145.  On such kernels we disable checksum offload
	// on our VXLAN and IPIP device.
	ChecksumOffloadBroken bool
	// IPIPDeviceIsL3 represent if ipip tunnels acts like other l3 devices
	IPIPDeviceIsL3 bool
	// KernelSideRouteFiltering is true if the kernel supports filtering netlink route dumps kernel-side.
	// This is much more efficient.
	KernelSideRouteFiltering bool
}

type FeatureDetectorIface interface {
	GetFeatures() *Features
	RefreshFeatures()
	FeatureGate(name string) string
}

func WithFeatureGates(gates map[string]string) Option {
	return func(detector *FeatureDetector) {
		detector.featureGates = gates
	}
}

type featureDetectorCommon struct {
	featureGates map[string]string
}

func (d *featureDetectorCommon) FeatureGate(name string) string {
	return d.featureGates[name]
}

var _ FeatureDetectorIface = (*FeatureDetector)(nil)
