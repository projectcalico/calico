# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
#
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
from numbers import Number

import ConfigParser
import logging
import socket

import pkg_resources
import re

from calico import common

# Logger
from calico.felix.futils import find_set_bits

log = logging.getLogger(__name__)

FELIX_IPT_GENERATOR_PLUGIN_NAME = "calico.felix.iptables_generator"

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
DEFAULT_SOURCES = [ENV, FILE, GLOBAL_ETCD, LOCAL_ETCD]


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
                 value_is_bool=False, value_is_int_list=False,
                 value_is_str_list=False):
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
        self.value_is_int_list = value_is_int_list
        self.value_is_str_list = value_is_str_list

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
                    # The int(..., 0) form barfs on non-strings so we need to
                    # check if we've already got a number in-hand.
                    if isinstance(value, Number):
                        self.value = int(value)
                    else:
                        self.value = int(value, 0)
                except (ValueError, TypeError):
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
            elif self.value_is_int_list:
                splits = str(value).split(",")
                ints = []
                for s in splits:
                    s = s.strip()
                    if not s:
                        continue
                    if re.match("^\d+$", s):
                        ints.append(int(s))
                    else:
                        raise ConfigException("Invalid list of ints", self)
                self.value = ints
            elif self.value_is_str_list:
                splits = str(value).split(',')
                self.value = [s.strip() for s in splits]
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
        been read, and the variables ETCD_ADDRS and HOSTNAME have been set and
        validated. The caller is then responsible for reading the remaining
        config from etcd and calling report_etcd_config with the returned
        values before the rest of the config structure can be used.

        :raises EtcdException
        """
        self.parameters = {}
        self.plugins = {}

        self.add_parameter("EtcdAddr", "Address and port for etcd",
                           "localhost:4001", sources=[ENV, FILE])
        self.add_parameter("FelixHostname", "Felix compute host hostname",
                           socket.gethostname(), sources=[ENV, FILE])
        self.add_parameter("EtcdScheme", "Protocol type for http or https",
                           "http", sources=[ENV, FILE])
        self.add_parameter("EtcdKeyFile", "Path to etcd key file",
                           "none", sources=[ENV, FILE])
        self.add_parameter("EtcdCertFile", "Path to etcd certificate file",
                           "none", sources=[ENV, FILE])
        self.add_parameter("EtcdCaFile", "Path to etcd CA certificate file",
                           "/etc/ssl/certs/ca-certificates.crt",
                           sources=[ENV, FILE])
        self.add_parameter("EtcdEndpoints", "Comma separated list of etcd "
                           "endpoints, of the form scheme://address:port.  "
                           "For example "
                           "\"https://1.2.3.4:2379,https://1.2.3.5:2379\".  "
                           "This option overrides EtcdScheme and EtcdAddr.",
                           "", sources=[ENV, FILE])

        self.add_parameter("StartupCleanupDelay",
                           "Delay before cleanup starts",
                           30, value_is_int=True)
        self.add_parameter("PeriodicResyncInterval",
                           "How often to do cleanups, seconds",
                           60 * 60, value_is_int=True)
        self.add_parameter("HostInterfacePollInterval",
                           "How often (in seconds) to poll for updates to "
                           "host endpoint IP addresses, or 0 to disable.", 10,
                           value_is_int=True)
        self.add_parameter("IptablesRefreshInterval",
                           "How often to refresh iptables state, in seconds",
                           60, value_is_int=True)
        self.add_parameter("MetadataAddr", "Metadata IP address or hostname",
                           "127.0.0.1")
        self.add_parameter("MetadataPort", "Metadata Port",
                           8775, value_is_int=True)
        self.add_parameter("InterfacePrefix", "Interface name prefix",
                           ["cali"], value_is_str_list=True)
        self.add_parameter("DefaultEndpointToHostAction",
                           "Action to take for packets that arrive from"
                           "an endpoint to the host.", "DROP")
        self.add_parameter("DropActionOverride",
                           "Override for the action taken when a packet would "
                           "normally be dropped by Calico's firewall rules. "
                           "This setting is useful when prototyping policy. "
                           "Note: if the policy is set to 'ACCEPT' or "
                           "'LOG-and-ACCEPT'; Calico's security is "
                           "disabled! "
                           "One of 'DROP', 'ACCEPT', 'LOG-and-DROP', "
                           "'LOG-and-ACCEPT'.",
                           "DROP")
        self.add_parameter("IgnoreLooseRPF",
                           "If set to true, Felix will ignore the kernel's "
                           "RPF check setting.  If set to false, Felix will "
                           "abort if the RPF setting is not 'strict'.  Should "
                           "only be set to true if workloads are incapable of "
                           "spoofing their source IP.  (For example, "
                           "unprivileged containers.)",
                           False, value_is_bool=True)
        self.add_parameter("ClusterGUID", "Unique cluster identifier",
                           "baddecaf")
        self.add_parameter("UsageReportingEnabled",
                           "If set to true, periodically report cluster "
                           "version, hostname, size and guid to "
                           "projectcalico.org.  Receive version deprecation / "
                           "security warnings.",
                           True, value_is_bool=True)
        self.add_parameter("LogFilePath",
                           "Path to log file", "/var/log/calico/felix.log")
        self.add_parameter("EtcdDriverLogFilePath",
                           "Path to log file for etcd driver",
                           "/var/log/calico/felix-etcd.log")
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
        self.add_parameter("IpInIpTunnelAddr",
                           "IPv4 address to set on the IP-in-IP device",
                           "none")
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
        self.add_parameter("IptablesMarkMask",
                           "Mask that Felix selects its IPTables Mark bits "
                           "from.  Should be a 32 bit hexadecimal number with "
                           "at least 8 bits set, none of which clash with any "
                           "other mark bits in use on the system.",
                           0xff000000, value_is_int=True)
        self.add_parameter("PrometheusMetricsEnabled",
                           "Whether to enable prometheus metrics.",
                           False, value_is_bool=True)
        self.add_parameter("PrometheusMetricsPort",
                           "Port on which to export Prometheus metrics.",
                           9091, value_is_int=True)
        self.add_parameter("EtcdDriverPrometheusMetricsPort",
                           "Port on which to export Prometheus metrics from "
                           "the etcd driver process.",
                           9092, value_is_int=True)

        self.add_parameter("FailsafeInboundHostPorts",
                           "Comma-separated list of numeric TCP ports to open "
                           "for all configured host endpoints.  Useful to "
                           "avoid accidentally cutting off (for example ssh) "
                           "connectivity via incorrect policy rules.  The "
                           "default value opens the ssh port, 22.",
                           [22], value_is_int_list=True)
        self.add_parameter("FailsafeOutboundHostPorts",
                           "Comma-separated list of numeric TCP ports to "
                           "allow traffic to from all host endpoints.  Useful "
                           "to avoid accidentally cutting off, for example, "
                           "access to etcd.  The default value allows "
                           "connectivity to etcd's default ports "
                           "2379,2380,4001 and 7001.",
                           [2379,2380,4001,7001], value_is_int_list=True)
        self.add_parameter("Ipv6Support",
                           "Whether IPv6 support is enabled.  If 'true', Felix "
                           "will program ip6tables rules and any IPv6 routes; "
                           "if 'false', Felix will not provide any IPv6 "
                           "function.  If set to 'auto', Felix will attempt "
                           "to detect whether the system supports IPv6 and "
                           "use it if it does.",
                           "auto")

        # The following setting determines which flavour of Iptables Generator
        # plugin is loaded.  Note: this plugin support is currently highly
        # experimental and may change significantly, or be removed completed,
        # in future releases. This config attribute is therefore not yet
        # publicly documented.
        self.add_parameter("IptablesGeneratorPlugin",
                           "Which IptablesGenerator Plugin to use.",
                           "default")

        # Read the environment variables, then the configuration file.
        self._read_env_vars()
        self._finish_update(final=False)
        self._read_cfg_file(config_path)
        self._finish_update(final=False)

        # Load the iptables generator plugin.
        self.plugins["iptables_generator"] = _load_plugin(
            FELIX_IPT_GENERATOR_PLUGIN_NAME,
            self.IPTABLES_GENERATOR_PLUGIN
        )()

        # Give plugins the opportunity to register any plugin specific
        # config attributes.   We've already loaded environment variables and
        # the configuration file at this point, so plugin specific attributes
        # will only be settable via etcd.
        for plugin in self.plugins.itervalues():
            plugin.register_config(self)

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

        :param final: Have we completed (rather than just read env and config
                      file)
        """

        self.HOSTNAME = self.parameters["FelixHostname"].value
        self.ETCD_SCHEME = self.parameters["EtcdScheme"].value
        self.ETCD_ENDPOINTS = self.parameters["EtcdEndpoints"].value
        self.ETCD_KEY_FILE = self.parameters["EtcdKeyFile"].value
        self.ETCD_CERT_FILE = self.parameters["EtcdCertFile"].value
        self.ETCD_CA_FILE = self.parameters["EtcdCaFile"].value
        self.STARTUP_CLEANUP_DELAY = \
            self.parameters["StartupCleanupDelay"].value
        self.RESYNC_INTERVAL = self.parameters["PeriodicResyncInterval"].value
        self.REFRESH_INTERVAL = \
            self.parameters["IptablesRefreshInterval"].value
        self.HOST_IF_POLL_INTERVAL_SECS = \
            self.parameters["HostInterfacePollInterval"].value
        self.METADATA_IP = self.parameters["MetadataAddr"].value
        self.METADATA_PORT = self.parameters["MetadataPort"].value
        self.IFACE_PREFIX = self.parameters["InterfacePrefix"].value
        self.DEFAULT_INPUT_CHAIN_ACTION = \
            self.parameters["DefaultEndpointToHostAction"].value
        self.LOGFILE = self.parameters["LogFilePath"].value
        self.DRIVERLOGFILE = self.parameters["EtcdDriverLogFilePath"].value
        self.LOGLEVFILE = self.parameters["LogSeverityFile"].value
        self.LOGLEVSYS = self.parameters["LogSeveritySys"].value
        self.LOGLEVSCR = self.parameters["LogSeverityScreen"].value
        self.IP_IN_IP_ENABLED = self.parameters["IpInIpEnabled"].value
        self.IP_IN_IP_MTU = self.parameters["IpInIpMtu"].value
        self.IP_IN_IP_ADDR = self.parameters["IpInIpTunnelAddr"].value
        self.REPORTING_INTERVAL_SECS = \
            self.parameters["ReportingIntervalSecs"].value
        self.REPORTING_TTL_SECS = self.parameters["ReportingTTLSecs"].value
        self.REPORT_ENDPOINT_STATUS = \
            self.parameters["EndpointReportingEnabled"].value
        self.ENDPOINT_REPORT_DELAY = \
            self.parameters["EndpointReportingDelaySecs"].value
        self.MAX_IPSET_SIZE = self.parameters["MaxIpsetSize"].value
        self.IPTABLES_GENERATOR_PLUGIN = \
            self.parameters["IptablesGeneratorPlugin"].value
        self.IPTABLES_MARK_MASK =\
            self.parameters["IptablesMarkMask"].value
        self.PROM_METRICS_ENABLED = \
            self.parameters["PrometheusMetricsEnabled"].value
        self.PROM_METRICS_PORT = \
            self.parameters["PrometheusMetricsPort"].value
        self.PROM_METRICS_DRIVER_PORT = \
            self.parameters["EtcdDriverPrometheusMetricsPort"].value
        self.FAILSAFE_INBOUND_PORTS = \
            self.parameters["FailsafeInboundHostPorts"].value
        self.FAILSAFE_OUTBOUND_PORTS = \
            self.parameters["FailsafeOutboundHostPorts"].value
        self.ACTION_ON_DROP = self.parameters["DropActionOverride"].value
        self.IGNORE_LOOSE_RPF = self.parameters["IgnoreLooseRPF"].value
        self.CLUSTER_GUID = self.parameters["ClusterGUID"].value
        self.USAGE_REPORT = self.parameters["UsageReportingEnabled"].value
        self.IPV6_SUPPORT = self.parameters["Ipv6Support"].value.lower()

        self._validate_cfg(final=final)

        # Now calculate config options that rely on parameter validation.

        # Determine the ETCD addresses to use.
        endpoints = [x.strip() for x in self.ETCD_ENDPOINTS.split(",")]
        if len(endpoints[0]) > 0:
            self.ETCD_SCHEME = endpoints[0].split("://")[0]
            self.ETCD_ADDRS = [e.split("://")[1] for e in endpoints]
        else:
            self.ETCD_SCHEME = self.parameters["EtcdScheme"].value
            self.ETCD_ADDRS = [self.parameters["EtcdAddr"].value]

        # Generate the IPTables mark masks we'll actually use internally.
        # From least to most significant bits of the mask we use them for:
        # - signalling that a profile accepted a packet
        # - signalling that a packet should move to the next policy tier.
        mark_mask = self.IPTABLES_MARK_MASK
        set_bits = find_set_bits(mark_mask)
        self.IPTABLES_MARK_ACCEPT = "0x%x" % next(set_bits)
        self.IPTABLES_MARK_NEXT_TIER = "0x%x" % next(set_bits)
        self.IPTABLES_MARK_ENDPOINTS = "0x%x" % next(set_bits)

        for plugin in self.plugins.itervalues():
            # Plugins don't get loaded and registered until we've read config
            # from the environment and file.   This means that they don't get
            # passed config until the final time through this function.
            assert final, "Plugins should only be loaded on the final " \
                          "config pass"
            plugin.store_and_validate_config(self)

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
        log.info("Reading config from %s", config_file)

        if not os.path.exists(config_file):
            log.info("Config file %s not present", config_file)
            return

        parser = ConfigParser.ConfigParser()
        parser.read(config_file)

        # The parser has an odd behaviour where a section called [DEFAULT] is
        # treated as a special case. If the user happens to use that name and
        # they happen not to put any other sections in the file then no config
        # is applied.  Explicitly grab the defaults now.
        cfg_dict = parser.defaults()
        # Build up the cfg dictionary from the file.
        for section in parser.sections():
            log.debug("Examining section %s", section)
            cfg_dict.update(dict(parser.items(section)))

        source = "Configuration file %s" % config_file

        for name, parameter in self.parameters.iteritems():
            # Config parameters are lower-cased by ConfigParser
            name = name.lower()
            if FILE in parameter.sources and name in cfg_dict:
                # This can validly be read from file.
                log.debug("Read %s = %s from file", name, cfg_dict[name])
                parameter.set(cfg_dict.pop(name), source)
        self._warn_unused_cfg(cfg_dict, source)

    def report_etcd_config(self, host_dict, global_dict):
        """
        Report configuration parameters read from etcd to the config
        component. This must be called only once, after configuration is
        initially read and before the config structure is used (except for
        ETCD_ADDRS and HOSTNAME).

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
        # Set default or python None value for each etcd "none" config value
        if self.ETCD_SCHEME.lower() == "none":
            self.ETCD_SCHEME = "http"
        if self.ETCD_KEY_FILE.lower() == "none":
            self.ETCD_KEY_FILE = None
        if self.ETCD_CERT_FILE.lower() == "none":
            self.ETCD_CERT_FILE = None
        if self.ETCD_CA_FILE == "none":
            self.ETCD_CA_FILE = None

        # Determine which etcd scheme and addresses will be used.
        addrs = []
        addr_opt = None
        scheme = None
        scheme_opt = None
        if self.ETCD_ENDPOINTS != "":
            addr_opt = "EtcdEndpoints"
            scheme_opt = "EtcdEndpoints"
            endpoints = [x.strip() for x in self.ETCD_ENDPOINTS.split(",")]
            try:
                for e in endpoints:
                    s, a = e.split("://")
                    addrs.append(a)
                    if scheme == None:
                        scheme = s
                    else:
                        if scheme != s:
                            raise ConfigException("Inconsistent protocols in "
                                                  "EtcdEndpoints.",
                                                  self.parameters[scheme_opt])
            except ValueError:
                raise ConfigException("Invalid format of EtcdEndpoints, must "
                                      "be `ENDPOINT[,ENDPOINT][,...]` where "
                                      "ENDPOINT:=`http[s]://ADDRESS:PORT`.",
                                      self.parameters[scheme_opt])
        else:
            addr_opt = "EtcdAddr"
            scheme_opt = "EtcdScheme"
            addrs = [self.parameters["EtcdAddr"].value]
            scheme = self.ETCD_SCHEME

        for addr in addrs:
            fields = addr.split(":")
            if len(fields) != 2:
                raise ConfigException("Invalid format for field - must be "
                                  "hostname:port", self.parameters[addr_opt])
            self._validate_addr(addr_opt, fields[0])

            try:
                int(fields[1])
            except ValueError:
                raise ConfigException("Invalid port in field",
                                      self.parameters[addr_opt])

        if scheme == "https":
            # key and certificate must be both specified or both not specified
            if bool(self.ETCD_KEY_FILE) != bool(self.ETCD_CERT_FILE):
                if not self.ETCD_KEY_FILE:
                    raise ConfigException("Missing etcd key file. Key and "
                                          "certificate must both be specified "
                                          "or both be blank.",
                                          self.parameters["EtcdKeyFile"])
                else:
                    raise ConfigException("Missing etcd certificate. Key and "
                                          "certificate must both be specified "
                                          "or both be blank.",
                                          self.parameters["EtcdCertFile"])

            # Make sure etcd key and certificate are readable
            if self.ETCD_KEY_FILE and self.ETCD_CERT_FILE:
                if not (os.path.isfile(self.ETCD_KEY_FILE) and
                        os.access(self.ETCD_KEY_FILE, os.R_OK)):
                    raise ConfigException("Cannot read key file. Key file "
                                          "must be a readable path.",
                                          self.parameters["EtcdKeyFile"])
                if not (os.path.isfile(self.ETCD_CERT_FILE) and
                        os.access(self.ETCD_CERT_FILE, os.R_OK)):
                    raise ConfigException("Cannot read cert file. Cert file "
                                          "must be a readable path.",
                                          self.parameters["EtcdCertFile"])

            # If Certificate Authority cert provided, check it's readable
            if (self.ETCD_CA_FILE and
                    not (os.path.isfile(self.ETCD_CA_FILE) and
                         os.access(self.ETCD_CA_FILE, os.R_OK))):
                raise ConfigException("Missing CA certificate or file is "
                                      "unreadable. Value must be readable "
                                      "file path.",
                                      self.parameters["EtcdCaFile"])
        elif scheme != "http":
            raise ConfigException("Invalid protocol scheme. Value must be one "
                                  "of: \"\", \"http\", \"https\".",
                                  self.parameters[scheme_opt])

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

        # Log files may be "None" (the literal string, case insensitive). In
        # this case no log file should be written.
        if self.LOGFILE.lower() == "none":
            self.LOGFILE = None
        if self.DRIVERLOGFILE.lower() == "none":
            self.DRIVERLOGFILE = None

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

        if self.IP_IN_IP_ADDR.lower() == "none":
            # IP-in-IP tunnel address is not required.
            self.IP_IN_IP_ADDR = None
        else:
            # IP-in-IP tunnel address must be a valid IP address if
            # supplied.
            self.IP_IN_IP_ADDR = self._validate_addr("IpInIpTunnelAddr",
                                                     self.IP_IN_IP_ADDR)

        if self.DEFAULT_INPUT_CHAIN_ACTION not in ("DROP", "RETURN", "ACCEPT"):
            raise ConfigException(
                "Invalid field value",
                self.parameters["DefaultEndpointToHostAction"]
            )

        if self.ACTION_ON_DROP not in ("DROP", "LOG-and-DROP", "ACCEPT",
                                       "LOG-and-ACCEPT"):
            log.warning("Unknown setting for DropActionOverride setting: %s, "
                        "defaulting to 'DROP'.", self.ACTION_ON_DROP)
            self.ACTION_ON_DROP = "DROP"
        if self.ACTION_ON_DROP.endswith("ACCEPT"):
            log.warning("Security disabled! DropActionOverride set to ACCEPT "
                        "or LOG-and-ACCEPT.  DROP rules will be replaced with"
                        "ACCEPT rules. ")

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

        if self.HOST_IF_POLL_INTERVAL_SECS < 0:
            log.warning("Host interface poll interval is negative, "
                        "defaulting to 10s.")
            self.HOST_IF_POLL_INTERVAL_SECS = 10

        if self.MAX_IPSET_SIZE <= 0:
            log.warning("Max ipset size is non-positive, defaulting to 2^20.")
            self.MAX_IPSET_SIZE = 2**20

        if self.IPTABLES_MARK_MASK <= 0:
            log.warning("Iptables mark mask contains insufficient bits, "
                        "defaulting to 0xff000000")
            self.IPTABLES_MARK_MASK = 0xff000000

        if self.IPTABLES_MARK_MASK > 0xffffffff:
            log.warning("Iptables mark mask out of range, "
                        "defaulting to 0xff000000")
            self.IPTABLES_MARK_MASK = 0xff000000

        if not 0 < self.PROM_METRICS_PORT < 65536:
            log.warning("Prometheus port out-of-range, defaulting to 9091")
            self.PROM_METRICS_PORT = 9091

        if not 0 < self.PROM_METRICS_DRIVER_PORT < 65536:
            log.warning("Etcd driver Prometheus port out-of-range, "
                        "defaulting to 9092")
            self.PROM_METRICS_DRIVER_PORT = 9092

        for name, ports in [
                ("FailsafeInboundHostPorts", self.FAILSAFE_INBOUND_PORTS),
                ("FailsafeOutboundHostPorts", self.FAILSAFE_OUTBOUND_PORTS)]:
            for p in ports:
                if not 0 < p < 65536:
                    raise ConfigException("Out-of-range port %s" % p,
                                          self.parameters[name])

        if self.IPV6_SUPPORT not in ("true", "false", "auto"):
            log.warning("Unrecognized value for Ipv6Support (%s), "
                        "defaulting to 'auto'", self.IPV6_SUPPORT)
            self.IPV6_SUPPORT = "auto"

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


def _load_plugin(plugin_entry_point, flavor):
    """
    Load a plugin for the specified entry point.   A package that implements a
    plugin exposes one or more named implementations (flavors) of one of more
    plugin entry points.  For example, the core Felix package registers a
    "default" implementation / flavor of the "calico.felix.iptables_generator"
    entry point (in setup.py).   There may be multiple packages installed, each
    offering different flavours of a given entry point.

    :param plugin_entry_point: The entry point for which we wish to load a
        plugin implementation.   E.g. "calico.felix.iptables_generator"
    :param flavor: The flavor / named implementation of the entry point we wish
        to load.  E.g. "default"
    :return: If an implementation of the requested entry point is available
        that matches the requested flavor then this function loads it and
        returns the function mapped by the entry point.   Otherwise this
        function raises ImportError.
    """
    for v in pkg_resources.iter_entry_points(plugin_entry_point, flavor):
        entry_point = v.load()
        log.info("Successfully loaded %s plugin: %s" %
                 (plugin_entry_point, flavor))
        return entry_point
    raise ImportError(
        'No plugin called "{0:s}" has been registered for entrypoint "{1:s}".'.
        format(flavor, plugin_entry_point))
