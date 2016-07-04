# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
felix.fplugin
~~~~~~~~~~~

A base class for all Felix plugins.

Note: This interface is currently HIGHLY EXPERIMENTAL.  It should not be
considered stable, and may change significantly, or be removed completely, in
future releases.

"""
import logging

_log = logging.getLogger(__name__)


class FelixPlugin(object):

    def register_config(self, config):
        """
        Define any plugin specific parameters that the plugin wishes to read
        from config. For each parameter, the plugin must call
        config.add_parameter.

        Note that plugin specific parameters can only be set via etcd (not
        via environment variables or config file) as plugins are not loaded
        until after the other config sources have been read.
        """
        pass

    def store_and_validate_config(self, config):
        """
        Plugin specific parameters will be available in config.parameters.
        Validate them (raising ConfigException) if necessary, and store off
        as required.

        This is also the opportunity for the plugin to store off any other
        global config that it is interested in.   This function isn't called
        until all core Felix config has been loaded, stored and validated.

        Any changes to global config after this function is called will result
        in Felix restarting.
        """
        pass

    def cleanup_complete(self, config):
        """
        Called when Felix's graceful resync period has completed and, for
        example, all unused ipsets and iptables have been successfully removed.
        """
        pass
