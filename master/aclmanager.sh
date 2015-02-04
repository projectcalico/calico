#!/bin/sh
exec calico-acl-manager --config-file=/config/acl_manager.cfg >>/var/log/calico/acl_manager_out.log 2>&1