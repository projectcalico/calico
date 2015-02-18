# -*- coding: utf-8 -*-
# Copyright (c) 2014 Metaswitch Networks
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
builds a singleton configuration object. Other modules should just import the
Config object and use the fields within it.
"""
import ConfigParser
import logging
import socket

from calico import common

# Logger
log = logging.getLogger(__name__)

class ConfigException(Exception):
    def __init__(self, message, path):
        super(ConfigException, self).__init__(message)
        self.file_path = path

    def __str__(self):
        return "%s (file path : %s)" % (self.message, self.file_path)

class Config(object):
    def __init__(self, config_path):
        self._KnownSections = set()
        self._KnownObjects  = set()

        self._config_path   = config_path

        self.read_cfg_file(config_path)

        self.EP_RETRY_INT_MS = int(
            self.get_cfg_entry("global",
                               "EndpointRetryTimeMillis",
                               500))
        self.RESYNC_INT_SEC  = int(
            self.get_cfg_entry("global",
                               "ResyncIntervalSecs",
                               1800))

        self.HOSTNAME        = self.get_cfg_entry("global",
                                                  "FelixHostname",
                                                  socket.gethostname())


        self.PLUGIN_ADDR     = self.get_cfg_entry("global",
                                                  "PluginAddress")
        self.ACL_ADDR        = self.get_cfg_entry("global",
                                                  "ACLAddress")
        self.METADATA_IP     = self.get_cfg_entry("global",
                                                  "MetadataAddr",
                                                  "127.0.0.1")
        self.IFACE_PREFIX    = self.get_cfg_entry("global",
                                                  "InterfacePrefix",
                                                  "tap")
        self.SUFFIX_LEN      = int(self.get_cfg_entry("global",
                                                      "InterfaceSuffixLength",
                                                      "11"))
        self.METADATA_PORT   = self.get_cfg_entry("global",
                                                  "MetadataPort",
                                                  "9697")
        self.LOCAL_ADDR      = self.get_cfg_entry("global",
                                                  "LocalAddress",
                                                  "*")
        self.LOGFILE         = self.get_cfg_entry("log",
                                                  "LogFilePath",
                                                  "None")
        self.LOGLEVFILE      = self.get_cfg_entry("log",
                                                  "LogSeverityFile",
                                                  "INFO")
        self.LOGLEVSYS       = self.get_cfg_entry("log",
                                                  "LogSeveritySys",
                                                  "ERROR")
        self.LOGLEVSCR       = self.get_cfg_entry("log",
                                                  "LogSeverityScreen",
                                                  "ERROR")

        self.CONN_TIMEOUT_MS   = int(
            self.get_cfg_entry("connection",
                               "ConnectionTimeoutMillis",
                               40000))
        self.CONN_KEEPALIVE_MS = int(
            self.get_cfg_entry("connection",
                               "ConnectionKeepaliveIntervalMillis",
                               5000))

        self.validate_cfg()

        self.warn_unused_cfg()

        # Finally, convert log level names into python log levels.
        loglevels = {"none":      None,
                     "debug":     logging.DEBUG,
                     "info":      logging.INFO,
                     "warn":      logging.WARNING,
                     "warning":   logging.WARNING,
                     "err":       logging.ERROR,
                     "error":     logging.ERROR,
                     "crit":      logging.CRITICAL,
                     "critical":  logging.CRITICAL}

        self.LOGLEVFILE = loglevels[self.LOGLEVFILE.lower()]
        self.LOGLEVSYS  = loglevels[self.LOGLEVSYS.lower()]
        self.LOGLEVSCR  = loglevels[self.LOGLEVSCR.lower()]

    def read_cfg_file(self, config_file):
        self._parser = ConfigParser.ConfigParser()
        self._parser.read(config_file)

        # Build up the list of sections.
        self._items = {}
        for section in self._parser.sections():
            self._items[section] = dict(self._parser.items(section))

    def get_cfg_entry(self, section, name, default=None):
        name    = name.lower()
        section = section.lower()

        if section not in self._items:
            raise ConfigException("Section %s missing from config file" %
                                  section, self._config_path)

        item = self._items[section]

        if name in item:
            value = item[name]
            del item[name]
        elif default is None:
            raise ConfigException("Variable %s not defined in section %s" %
                                  (name, section), self._config_path)
        else:
            value = default

        return value

    def validate_cfg(self):
        #*********************************************************************#
        #* Firewall that the config is not invalid.                          *#
        #*********************************************************************#
        if self.METADATA_IP.lower() == "none":
            # Metadata is not required.
            self.METADATA_IP = None
            self.METADATA_PORT = None
        else:
            # Metadata must be supplied as IP or address, but we store as IP
            self.METADATA_IP = self.validate_addr("MetadataAddr",
                                                  self.METADATA_IP)

            if not common.validate_port(self.METADATA_PORT):
                raise ConfigException("Invalid MetadataPort value : %s" %
                                      self.METADATA_PORT, self._config_path)

        #*********************************************************************#
        #* Now the plugin and ACL manager addresses. These are allowed to be *#
        #* IP addresses, or DNS resolvable hostnames.                        *#
        #*********************************************************************#
        self.validate_addr("PluginAddress", self.PLUGIN_ADDR)
        self.validate_addr("ACLAddress", self.ACL_ADDR)

        #*********************************************************************#
        #* Bind address must be * or an IPv4 address. We allow hostnames,    *#
        #* but resolve them before use.                                      *#
        #*********************************************************************#
        if self.LOCAL_ADDR != "*":
            self.LOCAL_ADDR = self.validate_addr("LocalAddress",
                                                 self.LOCAL_ADDR)

        #*********************************************************************#
        #* Log file may be "None" (the literal string, either provided or as *#
        #* default). In this case no log file should be written.             *#
        #*********************************************************************#
        if self.LOGFILE.lower() == "none":
            # Metadata is not required.
            self.LOGFILE = None

    def warn_unused_cfg(self):
        #*********************************************************************#
        #* Firewall that no unexpected items in the config file - i.e. ones  *#
        #* we have not used.                                                 *#
        #*********************************************************************#
        for section in self._items.keys():
            for lKey in self._items[section].keys():
                log.warning("Got unexpected item %s=%s in %s" %
                             (lKey, self._items[section][lKey], self._config_path))

    def validate_addr(self, name, addr):
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
                raise ConfigException("Blank %s value" % name,
                                      self._config_path)

            return socket.gethostbyname(addr)
        except socket.gaierror:
            raise ConfigException("Invalid or unresolvable %s value : %s" %
                                  (name, addr),
                                  self._config_path)
