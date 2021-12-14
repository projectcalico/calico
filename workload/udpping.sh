#!/bin/sh
echo hello | nc -u -w1 $1 69 | grep hello
