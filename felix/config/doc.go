// The config package provides config inheritance for Felix.
//
// It supports loading config from various sources, parsing and validating the
// config and merging the config according to the priority of the sources.
//
// # Usage
//
// To use it, create a Config object with:
//
//	config.New()
//
// Load some raw config using:
//
//	envConfig := config.LoadConfigFromEnvironment()
//	fileConfig, err := config.LoadConfigFile()
//
// Then feed it to the config object:
//
//	config.UpdateFrom(envConfig, config.EnvironmentVariable)
//	config.UpdateFrom(fileConfig, config.ConfigFile)
//
// The UpdateFrom() method returns an error, but, as a convenience, it also
// stores the error in config.Err.
//
// # Config inheritance
//
// Config from higher-priority sources overrides config from lower-priority
// sources.  The priorities, in increasing order of priority, are:
//
//	Default              // Default value of a parameter
//	DatastoreGlobal      // Cluster-wide config parameters from the datastore.
//	DatastorePerHost     // Per-host overrides from the datastore.
//	ConfigFile           // The local config file.
//	EnvironmentVariable  // Environment variables.
package config
