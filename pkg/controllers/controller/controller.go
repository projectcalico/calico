package controller

// Controller interface
type Controller interface {
	// Run method
	Run(threadiness int, reconcilerPeriod string, stopCh chan struct{})
}
