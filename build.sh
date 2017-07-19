#!/bin/sh
set -e
set -x

# Produce a binary - outputs to /dist/controller
mkdir /dist
go build -o /dist/controller
