#!/bin/bash

# Sanity check: the file is created by the Dockerfile.
if [ ! -f /in-the-container ]; then
  echo "Don't run this outside the container!"
  exit 1
fi

# those are needed by script itself
basicNeed=( "/bin/ls" "/bin/rm" "/bin/bash" "/bin/sh" "/bin/coreutils" )
# Array of basic tools needed by entrypoint and user_setup.
for i in "$@"; do
    if [[ ! " ${basicNeed[@]} " =~ " ${i} " ]]; then
        basicNeed+=("$i")
    fi
done
libraries=()

function findDependencies()
{
    t=$1
    dependencies=$(ldd "${t}" \
        | grep -P "\.so\.\d?" \
        | sed -e '/^[^\t]/ d' \
        | sed -e 's/\t//' \
        | sed -e 's/.*=..//' \
        | sed -e 's/ (0.*)//')
}

function cleanUp()
{
    if [[ -d $1 ]]; then
        for entry in "$1"/*; do
            cleanUp $entry
        done
        # Remove empty directory
        if [ -z "$(ls -A $1)" ]; then
            rmdir $1
        fi
    else
        remove=1
        for library in "${libraries[@]}"; do
            if [[ "$1" == *"$library"* ]]; then
                remove=0
                break
            fi
        done
        if [ "$remove" -eq 1 ]; then
            rm -f ${1}
        fi
    fi
}

# Get all shared libraries which are needed by basicNeed
echo "Finding dependencies for "${basicNeed[@]}""
for i in "${basicNeed[@]}"; do
    findDependencies $i
    for library in $dependencies; do 
        if test -f "$library"; then
             if [[ ! " ${libraries[@]} " =~ " ${library} " ]]; then
                libraries+=( "$library" )
            fi
        fi
    done
done

# Recursively find all that is needed
loop=1
while [ "$loop" -eq 1 ]; do 
    loop=0
    newDependencies=()
    for library in "${libraries[@]}"; do
        findDependencies $library
        for l in $dependencies; do
            if test -f "$l"; then
                if [[ ! " ${libraries[@]} " =~ " ${l} " ]]; then
                    newDependencies+=( "$l" )
                    loop=1
                fi
            fi
        done
    done
    for i in "${newDependencies[@]}"; do
        libraries+=( "$i" )
    done
done

# Recursively find all that is needed
loop=1
while [ "$loop" -eq 1 ]; do 
    loop=0
    newDependencies=()
    for library in "${libraries[@]}"; do
        rlink=$(readlink "$library")
        for l in $rlink; do
            if [[ ! " ${libraries[@]} " =~ " /lib64/${l} " ]]; then
                if test -f "/lib64/$l"; then              
                    loop=1
                    newDependencies+=( "/lib64/$l" )
                fi
            fi
        done
    done
    for i in "${newDependencies[@]}"; do
        libraries+=( "$i" )
    done
done

echo  "Keeping ${libraries[@]}"

paths=( "/lib64" "/usr/lib64" )
for i in  "${paths[@]}"; do
    cleanUp $i
done

paths=( "/bin" "/usr/bin" )
for i in  "${paths[@]}"; do
    for entry in "$i"/*; do
      remove=1
        for i in "${basicNeed[@]}"; do
            if [[ "$entry" == *"$i" ]]; then
                remove=0
                break
            fi
        done
        if [ "$remove" -eq 1 ]; then
            rm -f ${entry}
        fi
    done
done

rm /in-the-container 