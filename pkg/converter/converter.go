package converter

// Converter Responsible for conversion of given kubernetes object to equivalent calico object
type Converter interface {
	// Converts kubernetes object to calico representation of it.
	Convert(k8sObj interface{}) (interface{}, error)

	// Returns apporpriate key for the object
	GetKey(obj interface{}) string
}
