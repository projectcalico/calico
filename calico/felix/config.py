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
import re
import socket

#*****************************************************************************#
#* TODO: It would be nice to refactor so we did not have two identical       *#
#* definitions (we cannot import futils since it imports this module;        *#
#* ideally we should have this regex in a common global location).           *#
#*****************************************************************************#
INT_REGEX  = re.compile("^[0-9]+$")

class Config(object):
    def __init__(self, config_path):
        self._KnownSections = set()
        self._KnownObjects  = set()

        self.read_cfg_file(config_path)

        self.EP_RETRY_INT_MS = int(
            self.get_cfg_entry("global",
                               "EndpointRetryTimeMillis",
                               500))
        self.RESYNC_INT_SEC  = int(
            self.get_cfg_entry("global",
                               "ResyncIntervalSecs",
                               1800))
        self.PLUGIN_ADDR     = self.get_cfg_entry("global",
                                                  "PluginAddress")
        self.ACL_ADDR        = self.get_cfg_entry("global",
                                                  "ACLAddress")
        self.METADATA_IP     = self.get_cfg_entry("global",
                                                  "MetadataAddr",
                                                  "127.0.0.1")
        self.METADATA_PORT   = self.get_cfg_entry("global",
                                                  "MetadataPort",
                                                  "9697")
        self.LOGFILE         = self.get_cfg_entry("log",
                                                  "LogFilePath",
                                                  "felix.log")
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
                               2000))

        self.validate_cfg()

        self.warn_unused_cfg()

        # Finally, convert log level names into python log levels.
        loglevels = {"debug":     logging.DEBUG,
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
            raise Exception("Section %s missing from config file" % (section))

        item = self._items[section]

        if name in item:
            value = item[name]
            del item[name]

        elif default is None:
            raise Exception("Variable %s is not defined in section %s" %
                            (name, section))
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
            # Metadata can be supplied as IP or address, but we store as IP
            try:
                metadata_ip = socket.gethostbyname(self.METADATA_IP)
                self.METADATA_IP = metadata_ip
            except socket.gaierror:
                # Cannot resolve metadata_ip; neither an IP nor resolvable.
                raise Exception("Invalid MetadataAddr value : %s" %
                                self.METADATA_IP)
            if not INT_REGEX.match(self.METADATA_PORT):
                raise Exception("Invalid MetadataPort value : %s" %
                                self.METADATA_PORT)

    def warn_unused_cfg(self):
        #*********************************************************************#
        #* Firewall that no unexpected items in the config file - i.e. ones  *#
        #* we have not used.                                                 *#
        #*                                                                   *#
        #* TODO: No logging initialised yet, so really just have to print    *#
        #* for now.                                                          *#
        #*********************************************************************#
        for section in self._items.keys():
            for lKey in self._items[section].keys():
                print ("Got unexpected item %s=%s" %
                      (lKey, self._items[section][lKey]))
