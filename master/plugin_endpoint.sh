#!/bin/sh
exec python /plugin.py endpoint >>/var/log/calico/plugin_endpoint.log 2>&1