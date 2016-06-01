#!/usr/bin/env bash

set -x
set -e

# GetPython.
wget https://www.python.org/ftp/python/${PY_VERSION}/Python-${PY_VERSION}.tgz
# Install conntrack pre-reqs
wget http://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.1.tar.bz2
wget http://www.netfilter.org/projects/libmnl/files/libmnl-1.0.3.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_conntrack/files/libnetfilter_conntrack-1.0.5.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_cttimeout/files/libnetfilter_cttimeout-1.0.0.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_cthelper/files/libnetfilter_cthelper-1.0.0.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_acct/files/libnetfilter_acct-1.0.2.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.2.tar.bz2
wget http://www.netfilter.org/projects/libnetfilter_log/files/libnetfilter_log-1.0.1.tar.bz2
wget http://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.3.tar.bz2