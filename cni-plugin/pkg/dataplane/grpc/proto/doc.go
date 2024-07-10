//go:generate protoc --proto_path=. --go_out=. --go-grpc_out=. --go_opt=paths=source_relative cnibackend.proto

package proto

// The proto package defines a simple interface between the CNI plugin
// and a "dataplane driver", which can be used to interface the Calico
// CNI plugin with a custom dataplane, much like felix's dataplane
// abstraction allows to use Calico's policy engine with a non-kernel
// dataplane
