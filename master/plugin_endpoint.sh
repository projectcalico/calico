#!/bin/sh
exec python /plugin.py endpoint >>/var/log/calico/plugin_endpoint_console.log 2>&1