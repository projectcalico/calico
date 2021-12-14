#!/bin/sh

# Get all golang files in the repo, excluding the vendor dir.
files=$(find . -path ./vendor -prune -o -name "*.go" -type f | grep -v vendor)
nocopyright=""
for f in $files
do
	# For each file, check if it contains "Copyright" in the first line.
	exists=$(head -n 1 $f | grep "Copyright")
	if [ -z "$exists" ]; then 
		nocopyright="$nocopyright\n$f"
	fi 
done

# If any files are missing a copyright, then exit with an error code.
if [ ! -z "$nocopyright" ]; then 
	echo "Files missing copyright: \n$nocopyright"
	exit 1
fi
