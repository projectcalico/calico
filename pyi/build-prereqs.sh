#!/usr/bin/env bash
set -x
set -e

tar xzf Python-${PY_VERSION}.tgz
pushd Python-${PY_VERSION} 
./configure --prefix=/usr/local --enable-shared
make && make altinstall
popd

wget "https://bootstrap.pypa.io/get-pip.py"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
python2.7 get-pip.py

# Build and install conntrack and its libraries.
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
for lib in libnfnetlink-1.0.1 libmnl-1.0.3 libnetfilter_conntrack-1.0.5 \
           libnetfilter_cttimeout-1.0.0 libnetfilter_cthelper-1.0.0 \
           libnetfilter_acct-1.0.2 libnetfilter_queue-1.0.2 libnetfilter_log-1.0.1 \
           libnetfilter_cttimeout-1.0.0 conntrack-tools-1.4.3;
do
    tar xjf ${lib}.tar.bz2
    pushd ${lib}
    ./configure
    make
    make install
    popd
done
