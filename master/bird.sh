#!/bin/sh
exec bird -s bird.ctl -d -c /config/bird.conf >>/var/log/calico/bird.log 2>&1