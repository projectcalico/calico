package creds

// Credentials are the credentials published by the Flexvolume driver
type Credentials struct {
	// UID is the unique identifier for the workload.
	UID            string
	// Workload is the name of the workload.
	Workload       string
	// Namespace is the namespace of the workload.
	Namespace      string
	// ServiceAccount is the service account of the workload.
	ServiceAccount string
}
