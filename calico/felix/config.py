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
from calico.felix import fetcd

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


class ConfigException(Exception):
    def __init__(self, message, source):
        super(ConfigException, self).__init__(message)
        self.message = message
        self.source = source

    def __str__(self):
        return "%s (data source : %s)" % (self.message, self.source)

class Config(object):
    def __init__(self, config_path):
        """
        Create a config.
        :raises EtcdException
        """
        self._KnownSections = set()
        self._KnownObjects  = set()

        self._config_path = config_path
        self._items = {}

        self.read_cfg_file(config_path)

        self.ETCD_PORT = self.get_cfg_entry("global", "EtcdPort", 4001)

        self.HOSTNAME = self.get_cfg_entry("global",
                                           "FelixHostname",
                                           socket.gethostname())

        self.METADATA_IP = "127.0.0.1"
        self.METADATA_PORT = "8775"
        self.RESYNC_INT_SEC = 1800
        self.IFACE_PREFIX = None
        self.LOGFILE = "/var/log/calico/felix.log"
        self.LOGLEVFILE = "INFO"
        self.LOGLEVSYS = "ERROR"
        self.LOGLEVSCR = "ERROR"

        self.LOGLEVFILE = LOGLEVELS.get(self.LOGLEVFILE.lower(), logging.DEBUG)
        self.LOGLEVSYS = LOGLEVELS.get(self.LOGLEVSYS.lower(), logging.DEBUG)
        self.LOGLEVSCR = LOGLEVELS.get(self.LOGLEVSCR.lower(), logging.DEBUG)

    def update_config(self, cfg_dict):
        self.METADATA_IP = cfg_dict.pop("MetadataAddr", "127.0.0.1")
        self.METADATA_PORT = cfg_dict.pop("MetadataPort", "8775")
        self.RESYNC_INT_SEC = int(cfg_dict.pop("ResyncIntervalSecs", "1800"))
        self.IFACE_PREFIX = cfg_dict.pop("InterfacePrefix", None)
        self.LOGFILE = cfg_dict.pop("LogFilePath", "/var/log/calico/felix.log")
        self.LOGLEVFILE = cfg_dict.pop("LogSeverityFile", "INFO")
        self.LOGLEVSYS = cfg_dict.pop("LogSeveritySys", "ERROR")
        self.LOGLEVSCR = cfg_dict.pop("LogSeverityScreen", "ERROR")

        self.LOGLEVFILE = LOGLEVELS.get(self.LOGLEVFILE.lower(), logging.DEBUG)
        self.LOGLEVSYS = LOGLEVELS.get(self.LOGLEVSYS.lower(), logging.DEBUG)
        self.LOGLEVSCR = LOGLEVELS.get(self.LOGLEVSCR.lower(), logging.DEBUG)

        self.validate_cfg()

        self.warn_unused_cfg(cfg_dict)

    def read_cfg_file(self, config_file):
        self._parser = ConfigParser.ConfigParser()
        self._parser.read(config_file)

        # Build up the list of sections.
        for section in self._parser.sections():
            self._items[section] = dict(self._parser.items(section))

        if not self._items:
            log.warning("Configuration file %s empty or does not exist",
                        config_file)


    def get_cfg_entry(self, section, name, default=None):
        name    = name.lower()
        section = section.lower()

        if section not in self._items:
            if default is not None:
                return default
            else:
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
                                      self.METADATA_PORT,
                                      "etcd:/calico/config/MetadataPort")


        if self.IFACE_PREFIX is None:
            raise ConfigException("Missing InterfacePrefix value",
                                  "etcd:/calico/config/InterfacePrefix")

        #*********************************************************************#
        #* Log file may be "None" (the literal string, either provided or as *#
        #* default). In this case no log file should be written.             *#
        #*********************************************************************#
        if self.LOGFILE.lower() == "none":
            # Metadata is not required.
            self.LOGFILE = None

    def warn_unused_cfg(self, cfg_dict):
        #*********************************************************************#
        #* Firewall that no unexpected items in the config file - i.e. ones  *#
        #* we have not used.                                                 *#
        #*********************************************************************#
        for section in self._items.keys():
            for lKey in self._items[section].keys():
                log.warning("Got unexpected item %s=%s in %s",
                            lKey, self._items[section][lKey], self._config_path)

        for lKey in cfg_dict:
            log.warning("Got unexpected etcd config item %s=%s",
                        lKey, cfg_dict[lKey])


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
