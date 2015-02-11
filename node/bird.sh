#!/bin/sh
exec bird -s bird.ctl -d -c /config/bird.cfg >>/var/log/calico/bird.log 2>&1