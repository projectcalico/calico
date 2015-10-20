# -*- coding: utf-8 -*-
# Copyright (c) 2014, 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
felix.config
~~~~~~~~~~~~

Configuration management for Felix.

On instantiation, this module automatically parses the configuration file and
builds a singleton configuration object. That object may (once) be changed by
etcd configuration being reported back to it.
"""
import os

import ConfigParser
import logging
import socket

from calico import common

# Logger
log = logging.getLogger(__name__)

# Convert log level names into python log levels.
LOGLEVELS = {"none":      None,
             "debug":     logging.DEBUG,
             "info":      logging.INFO,
             "warn":      logging.WARNING,
             "warning":   logging.WARNING,
             "err":       logging.ERROR,
             "error":     logging.ERROR,
             "crit":      logging.CRITICAL,
             "critical":  logging.CRITICAL}

# Sources of a configuration parameter. The order is highest-priority first.
DEFAULT = "Default"
ENV = "Environment variable"
FILE = "Configuration file"
GLOBAL_ETCD = "Global etcd configuration"
LOCAL_ETCD = "Host specific etcd configuration"
DEFAULT_SOURCES = [ ENV, FILE, GLOBAL_ETCD, LOCAL_ETCD ]


class ConfigException(Exception):
    def __init__(self, message, parameter):
        super(ConfigException, self).__init__(message)
        self.message = message
        self.parameter = parameter

    def __str__(self):
        return "%s (value %r for %s (%s), read from %r)" \
            % (self.message,
               self.parameter.value,
               self.parameter.name,
               self.parameter.description,
               self.parameter.active_source)


class ConfigParameter(object):
    """
    A configuration parameter. This contains the following information.
    - The name of the field.
    - Where the location can validly be read from
    - The current value
    - Where the value was read from
    """
    def __init__(self, name, description, default,
                 sources=DEFAULT_SOURCES, value_is_int=False,
                 value_is_bool=False):
        """
        Create a configuration parameter.
        :param str description: Description for logging
        :param list sources: List of valid sources to try
        :param str default: Default value
        :param bool value_is_int: Integer value?
        """
        self.description = description
        self.name = name
        self.sources = sources
        self.value = default
        self.active_source = None
        self.value_is_int = value_is_int
        self.value_is_bool = value_is_bool

    def set(self, value, source):
        """
        Set a value of a parameter - unless already set.
        :param value: value
        :param source: source; for example "Configuration file /etc/felix.cfg"
        """
        if self.active_source is None:
            log.debug("Read value %r for %s (%s) from %r",
                      value,
                      self.name,
                      self.description,
                      source)

            self.active_source = source

            if self.value_is_int:
                # Set value before the call to int, so the ConfigException has
                # the right value if / when it goes wrong.
                self.value = value
                try:
                    self.value = int(value)
                except ValueError:
                    raise ConfigException("Field was not integer",
                                          self)
            elif self.value_is_bool:
                lower_val = str(value).lower()
                log.debug("Parsing %r as a Boolean.", lower_val)
                if lower_val in ("true", "1", "yes", "y", "t"):
                    self.value = True
                elif lower_val in ("false", "0", "no", "n", "f"):
                    self.value = False
                else:
                    raise ConfigException("Field was not a valid Boolean",
                                          self)
            else:
                # Calling str in principle can throw an exception, but it's
                # hard to see how in practice, so don't catch and wrap.
                self.value = str(value)
        else:
            log.warning("Ignore %r value for %s (%s) - already set from %r",
                        source,
                        self.name,
                        self.description,
                        self.active_source)


class Config(object):
    def __init__(self, config_path):
        """
        Create a config. This reads data from the following sources.
        - Environment variables
        - Configuration file (/etc/calico/felix.cfg)
        - per-host etcd (/calico/vX/config)
        - global etcd (/calico/vX/host/<host>/config)

        After object creation, the environment variables and config file have
        been read, and the variables ETCD_ADDR and HOSTNAME have been set and
        validated. The caller is then responsible for reading the remaining
        config from etcd and calling report_etcd_config with the returned
        values before the rest of the config structure can be used.

        :raises EtcdException
        """
        self.parameters = {}

        self.add_parameter("EtcdAddr", "Address and port for etcd",
                           "localhost:4001", sources=[ENV, FILE])
        self.add_parameter("FelixHostname", "Felix compute host hostname",
                           socket.gethostname(), sources=[ENV, FILE])

        self.add_parameter("StartupCleanupDelay",
                           "Delay before cleanup starts",
                           30, value_is_int=True)
        self.add_parameter("PeriodicResyncInterval",
                           "How often to do cleanups, seconds",
                           60 * 60, value_is_int=True)
        self.add_parameter("IptablesRefreshInterval",
                           "How often to refresh iptables state, in seconds",
                           60, value_is_int=True)
        self.add_parameter("MetadataAddr", "Metadata IP address or hostname",
                           "127.0.0.1")
        self.add_parameter("MetadataPort", "Metadata Port",
                           8775, value_is_int=True)
        self.add_parameter("InterfacePrefix", "Interface name prefix", None)
        self.add_parameter("DefaultEndpointToHostAction",
                           "Action to take for packets that arrive from"
                           "an endpoint to the host.", "DROP")
        self.add_parameter("LogFilePath",
                           "Path to log file", "/var/log/calico/felix.log")
        self.add_parameter("LogSeverityFile",
                           "Log severity for logging to file", "INFO")
        self.add_parameter("LogSeveritySys",
                           "Log severity for logging to syslog", "ERROR")
        self.add_parameter("LogSeverityScreen",
                           "Log severity for logging to screen", "ERROR")
        self.add_parameter("IpInIpEnabled",
                           "IP-in-IP device support enabled", False,
                           value_is_bool=True)
        self.add_parameter("IpInIpMtu",
                           "MTU to set on the IP-in-IP device", 1440,
                           value_is_int=True)
        self.add_parameter("ReportingIntervalSecs",
                           "Status reporting interval in seconds",
                           30, value_is_int=True)
        self.add_parameter("ReportingTTLSecs",
                           "Status report time to live in seconds",
                           90, value_is_int=True)
        self.add_parameter("EndpointReportingEnabled",
                           "Whether Felix should report per-endpoint status "
                           "into etcd",
                           False, value_is_bool=True)
        self.add_parameter("EndpointReportingDelaySecs",
                           "Minimum delay between per-endpoint status reports",
                           1, value_is_int=True)
        self.add_parameter("MaxIpsetSize",
                           "Maximum size of the ipsets that Felix uses to "
                           "represent profile tag memberships.  Should be set "
                           "to a value larger than the expected number of "
                           "IP addresses using a single tag.",
                           2**20, value_is_int=True)

        # Read the environment variables, then the configuration file.
        self._read_env_vars()
        self._read_cfg_file(config_path)
        self._finish_update(final=False)

    def add_parameter(self, name, description, default, **kwargs):
        """
        Put a parameter in the parameter dictionary.
        """
        self.parameters[name] = ConfigParameter(
            name, description, default, **kwargs)

    def _finish_update(self, final=False):
        """
        Config has been completely read. Called twice - once after reading from
        environment and config file (so we should be able to access etcd), and
        once after reading from etcd (so we have all the config ready to go).

        Responsible for :
        - storing the parameters in the relevant fields in the structure
        - validating the configuration is valid (for this stage in the process)
        - updating logging parameters

        Note that we complete the logging even before etcd configuration
        changes are read. Hence, for example, if logging to file is turned on
        after reading environment variables and config file, then the log file
        is created and logging to it starts - even if later on etcd
        configuration turns the file off. That's because we must log if etcd
        configuration load fails, and not having the log file early enough is
        worse.

        :param final: Have we completed (rather than just read env and config file)
        """
        self.ETCD_ADDR = self.parameters["EtcdAddr"].value
        self.HOSTNAME = self.parameters["FelixHostname"].value
        self.STARTUP_CLEANUP_DELAY = self.parameters["StartupCleanupDelay"].value
        self.RESYNC_INTERVAL = self.parameters["PeriodicResyncInterval"].value
        self.REFRESH_INTERVAL = self.parameters["IptablesRefreshInterval"].value
        self.METADATA_IP = self.parameters["MetadataAddr"].value
        self.METADATA_PORT = self.parameters["MetadataPort"].value
        self.IFACE_PREFIX = self.parameters["InterfacePrefix"].value
        self.DEFAULT_INPUT_CHAIN_ACTION = \
            self.parameters["DefaultEndpointToHostAction"].value
        self.LOGFILE = self.parameters["LogFilePath"].value
        self.LOGLEVFILE = self.parameters["LogSeverityFile"].value
        self.LOGLEVSYS = self.parameters["LogSeveritySys"].value
        self.LOGLEVSCR = self.parameters["LogSeverityScreen"].value
        self.IP_IN_IP_ENABLED = self.parameters["IpInIpEnabled"].value
        self.IP_IN_IP_MTU = self.parameters["IpInIpMtu"].value
        self.REPORTING_INTERVAL_SECS = self.parameters["ReportingIntervalSecs"].value
        self.REPORTING_TTL_SECS = self.parameters["ReportingTTLSecs"].value
        self.REPORT_ENDPOINT_STATUS = \
            self.parameters["EndpointReportingEnabled"].value
        self.ENDPOINT_REPORT_DELAY = \
            self.parameters["EndpointReportingDelaySecs"].value
        self.MAX_IPSET_SIZE = self.parameters["MaxIpsetSize"].value

        self._validate_cfg(final=final)

        # Update logging.
        common.complete_logging(self.LOGFILE,
                                self.LOGLEVFILE,
                                self.LOGLEVSYS,
                                self.LOGLEVSCR,
                                gevent_in_use=True)

        if final:
            # Log configuration - the whole lot of it.
            for name, parameter in self.parameters.iteritems():
                log.info("Parameter %s (%s) has value %r read from %s",
                         name,
                         parameter.description,
                         parameter.value,
                         parameter.active_source)

    def _read_env_vars(self):
        """
        Read all of the variables from the environment.
        """
        for name, parameter in self.parameters.iteritems():
            # All currently defined config parameters have ENV as a valid
            # source.
            assert(ENV in parameter.sources)
            # ENV is the first source, so we can assert that using defaults.
            assert(parameter.active_source is None)

            env_var = ("FELIX_%s" % name).upper()
            if env_var in os.environ:
                parameter.set(os.environ[env_var],
                              "Environment variable %s" % env_var)

    def _read_cfg_file(self, config_file):
        parser = ConfigParser.ConfigParser()
        parser.read(config_file)
        cfg_dict = {}

        # Build up the cfg dictionary from the file.
        for section in parser.sections():
            cfg_dict.update(dict(parser.items(section)))

        source = "Configuration file %s" % config_file

        for name, parameter in self.parameters.iteritems():
            # Config parameters are lower-cased by ConfigParser
            name = name.lower()
            if FILE in parameter.sources and name in cfg_dict:
                # This can validly be read from file.
                parameter.set(cfg_dict.pop(name), source)
        self._warn_unused_cfg(cfg_dict, source)

    def report_etcd_config(self, host_dict, global_dict):
        """
        Report configuration parameters read from etcd to the config
        component. This must be called only once, after configuration is
        initially read and before the config structure is used (except for
        ETCD_ADDR and HOSTNAME).

        :param host_dict: Dictionary of etcd parameters
        :param global_dict: Dictionary of global parameters
        :raises ConfigException
        """
        log.debug("Configuration reported from etcd")
        for source, cfg_dict in ((LOCAL_ETCD, host_dict),
                                 (GLOBAL_ETCD, global_dict)):
            for name, parameter in self.parameters.iteritems():
                if source in parameter.sources and name in cfg_dict:
                    parameter.set(cfg_dict.pop(name), source)

            self._warn_unused_cfg(cfg_dict, source)

        self._finish_update(final=True)

    def _validate_cfg(self, final=True):
        """
        Firewall that the config is not invalid. Called twice, once when
        environment variables and config file have been read, and once
        after those plus the etcd configuration have been read.
        :param final: Is this after final etcd config has been read?
        :raises ConfigException
        """
        fields = self.ETCD_ADDR.split(":")
        if len(fields) != 2:
            raise ConfigException("Invalid format for field - must be "
                                  "hostname:port", self.parameters["EtcdAddr"])
        self._validate_addr("EtcdAddr", fields[0])

        try:
            int(fields[1])
        except ValueError:
            raise ConfigException("Invalid port in field",
                                  self.parameters["EtcdAddr"])

        try:
            self.LOGLEVFILE = LOGLEVELS[self.LOGLEVFILE.lower()]
        except KeyError:
            raise ConfigException("Invalid log level",
                                  self.parameters["LogSeverityFile"])

        try:
            self.LOGLEVSYS = LOGLEVELS[self.LOGLEVSYS.lower()]
        except KeyError:
            raise ConfigException("Invalid log level",
                                  self.parameters["LogSeveritySys"])

        try:
            self.LOGLEVSCR = LOGLEVELS[self.LOGLEVSCR.lower()]
        except KeyError:
            raise ConfigException("Invalid log level",
                                  self.parameters["LogSeverityScreen"])

        # Log file may be "None" (the literal string, case insensitive). In
        # this case no log file should be written.
        if self.LOGFILE.lower() == "none":
            self.LOGFILE = None

        if self.METADATA_IP.lower() == "none":
            # Metadata is not required.
            self.METADATA_IP = None
            self.METADATA_PORT = None
        else:
            # Metadata must be supplied as IP or address, but we store as IP
            self.METADATA_IP = self._validate_addr("MetadataAddr",
                                                   self.METADATA_IP)

            if not common.validate_port(self.METADATA_PORT):
                raise ConfigException("Invalid field value",
                                      self.parameters["MetadataPort"])

        if self.DEFAULT_INPUT_CHAIN_ACTION not in ("DROP", "RETURN", "ACCEPT"):
            raise ConfigException(
                "Invalid field value",
                self.parameters["DefaultEndpointToHostAction"]
            )

        # For non-positive time values of reporting interval we set both
        # interval and ttl to 0 - i.e. status reporting is disabled.
        if self.REPORTING_INTERVAL_SECS <= 0:
            log.warning("Reporting disabled.")
            self.REPORTING_TTL_SECS = 0
            self.REPORTING_INTERVAL_SECS = 0

        # Ensure the TTL is longer than the reporting interval, defaulting
        # it if not.
        if (self.REPORTING_TTL_SECS <= self.REPORTING_INTERVAL_SECS or
                self.REPORTING_TTL_SECS == 0):
            log.warning("Reporting TTL set to %s.", self.REPORTING_TTL_SECS)
            self.REPORTING_TTL_SECS = self.REPORTING_INTERVAL_SECS * 5/2

        if self.ENDPOINT_REPORT_DELAY < 0:
            log.warning("Endpoint status delay is negative, defaulting to 1.")
            self.ENDPOINT_REPORT_DELAY = 1

        if self.MAX_IPSET_SIZE <= 0:
            log.warning("Max ipset size is non-positive, defaulting to 2^20.")
            self.MAX_IPSET_SIZE = 2**20

        if not final:
            # Do not check that unset parameters are defaulted; we have more
            # config to read.
            return

        for parameter in self.parameters.itervalues():
            if parameter.value is None:
                # No value, not even a default
                raise ConfigException("Missing undefaulted value",
                                      parameter)

    def _warn_unused_cfg(self, cfg_dict, source):
        # Warn about any unexpected items - i.e. ones we have not used.
        for lKey in cfg_dict:
            log.warning("Got unexpected config item %s=%s",
                        lKey, cfg_dict[lKey])

    def _validate_addr(self, name, addr):
        """
        Validate an address, returning the IP address it resolves to. If the
        address cannot be resolved then an exception is returned.

        Parameters :
        - name of the field, for use in logging
        - address to resolve
        """
        try:
            stripped_addr = addr.strip()
            if not stripped_addr:
                raise ConfigException("Blank value",
                                      self.parameters[name])

            return socket.gethostbyname(addr)
        except socket.gaierror:
            raise ConfigException("Invalid or unresolvable value",
                                  self.parameters[name])
