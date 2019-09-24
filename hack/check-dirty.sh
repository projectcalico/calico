#!/bin/bash
if [[ $(git status --porcelain) != '' ]]; then
	echo "$(git status)"
	echo ""
	echo "ERROR: Local working tree is not clean. Make sure clean builds do not produce a dirty tree."
	echo ""
	exit 1
fi
