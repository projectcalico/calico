#!/bin/sh
exec python /plugin.py network >>/var/log/calico/plugin_network.log 2>&1