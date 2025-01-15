#!/bin/sh

OUT_DIR=$1

if [ -z $1 ] ; then
    OUT_DIR="."
fi
echo $OUT_DIR

BASE=`dirname $0`

ssh-keygen -m PEM -b 2048 -t rsa -f $OUT_DIR/cert.key -N ""
openssl req -x509 -new -nodes -key $OUT_DIR/cert.key -sha256 -out $OUT_DIR/cert.pem -config $BASE/openssl.cnf -days 99999

