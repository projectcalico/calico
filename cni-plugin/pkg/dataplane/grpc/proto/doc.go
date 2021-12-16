//go:generate protoc -I=. --gogo_out=plugins=grpc:. ./cnibackend.proto

package proto

// The proto package defines a simple interface between the CNI plugin
// and a "dataplane driver", which can be used to interface the Calico
// CNI plugin with a custom dataplane, much like felix's dataplane
// abstraction allows to use Calico's policy engine with a non-kernel
// dataplane
