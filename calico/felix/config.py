# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
felix.config
~~~~~~~~~~~~

Configuration management for Felix.

This module behaves slightly oddly: on instantiation it automatically parses
the configuration file and builds a singleton configuration object. This
guarantees that all configuration lives in a single place.
"""
import ConfigParser
import logging
import argparse


# This is the default configuration path - we expect in most cases that the
# configuration file path is passed in on the command line.
CONFIG_FILE_PATH = 'felix.cfg'


class _Config(object):
    def __init__(self):
        self._KnownSections = set()
        self._KnownObjects  = set()

        # Parse command line args.
        parser = argparse.ArgumentParser(description='Felix (Calico agent)')
        parser.add_argument('-c', '--config-file', dest='config_file')
        args = parser.parse_args()

        self._parser = ConfigParser.ConfigParser()
        self._parser.read(args.config_file or CONFIG_FILE_PATH)

        # Build up the list of sections.
        self._items    = {}
        for section in self._parser.sections():
            self._items[section] = dict(self._parser.items(section))

        self.EP_RETRY_INT_MS = self.get_cfg_entry("global", "EndpointRetryTimeMillis", 500)
        self.RESYNC_INT_SEC  = self.get_cfg_entry("global", "ResyncIntervalSecs", 1800)
        self.PLUGIN_ADDR     = self.get_cfg_entry("global", "PluginAddress", None)
        self.ACL_ADDR        = self.get_cfg_entry("global", "ACLAddress", None)

        self.LOGFILE         = self.get_cfg_entry("log", "LogFilePath", "/tmp/felix.log")
        self.LOGLEVFILE      = self.get_cfg_entry("log", "LogSeverityFile", "INFO")
        self.LOGLEVSYS       = self.get_cfg_entry("log", "LogSeveritySys", "ERROR")
        self.LOGLEVSCR       = self.get_cfg_entry("log", "LogSeverityScreen", "DEBUG")

        self.CONN_TIMEOUT_MS   = self.get_cfg_entry("connection",
                                                    "ConnectionTimeoutMillis",
                                                    30000)
        self.CONN_KEEPALIVE_MS = self.get_cfg_entry("connection",
                                                    "ConnectionKeepaliveIntervalMillis",
                                                    2000)
        self.CONN_RETRY_MS     = self.get_cfg_entry("connection",
                                                    "ConnectionRetryIntervalMillis",
                                                    15000)

        # Firewall that no unexpected items in the config file - i.e. ones we
        # have not used.
        # TODO: No logging initialised yet, so really just have to print for now.
        for section in self._items.keys():
            for lKey in self._items[section].keys():
                print "Got unexpected item %s=%s" % (lKey, self._items[section][lKey])

        # Finally, some munging.
        _loglevels = { "debug"    : logging.DEBUG,
                       "info"     : logging.INFO,
                       "warn"     : logging.WARNING,
                       "warning"  : logging.WARNING,
                       "err"      : logging.ERROR,
                       "error"    : logging.ERROR,
                       "crit"     : logging.CRITICAL,
                       "critical" : logging.CRITICAL }

        self.LOGLEVFILE = _loglevels[self.LOGLEVFILE.lower()]
        self.LOGLEVSYS  = _loglevels[self.LOGLEVSYS.lower()]
        self.LOGLEVSCR  = _loglevels[self.LOGLEVSCR.lower()]

    def get_cfg_entry(self, section, name, default):
        if section.lower() not in self._items:
            raise Exception("Section %s missing from config file" % (section))

        item  = self._items[section.lower()]

        if name.lower() in item:
            value = item[name.lower()]
            del item[name.lower()]
        elif default is None:
            raise Exception("Variable %s is not defined in section %s" % (name, section))
        else:
            value = default

        return value

Config = _Config()
