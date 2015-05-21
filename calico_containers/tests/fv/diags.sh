#!/bin/sh
set -e
set -x

dist/calicoctl diags | grep "https://transfer.sh/"
