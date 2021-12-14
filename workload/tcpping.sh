#!/bin/sh
echo hello | nc -w1 $1 80 | grep hello
