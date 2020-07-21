#!/bin/bash

# 1) the idea of this script is to start with list of tools needed (passed as an argument + the tools script itself needs)
# 2) Find all libraries such a tools depend on.
# 3) Remove everything from /lib64 and /usr/lib64 but the libraries found in #2
# 4) Remove everything from /bin and /usr/bin but the tools needed (#1) 

# Sanity check: the file is created by the Dockerfile. 
# Abort the script is such a file is not present. This will avoid accidentally running the script.
if [ ! -f /in-the-container ]; then
  echo "Don't run this outside the container!"
  exit 1
fi

# folllowing are needed by script itself
basicNeed=( "/bin/ls" "/bin/rm" "/bin/bash" "/bin/sh" "/bin/coreutils" )
# Array of basic tools needed by entrypoint and user_setup.
for i in "$@"; do
    if [[ ! " ${basicNeed[@]} " =~ " ${i} " ]]; then
        basicNeed+=("$i")
    fi
done
libraries=()

# Fine all libraries for the passed argument.
# Output of following command returns back full path of each dependency. 
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

# Recursively removes all that is not needed.
# If the argurment is a directory, then it recursively consider all subdirectories and files.
# A directory is kept only if is not empty.
# If the argument is a file, then it is kept only if present in ${libraries[@]} (which by the time this method is
# invoked contains already all libraries that are needed).
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
# basicNeed is the list of tools the script itself depend on plus any tool passed as argument of the script
# from Dockerfile.
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

# Recursively find all that is needed (a needed library might depend itself on other libraries).
# Everytime we find a new library we depend on, a new iteration is needed.
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

paths=( "/lib64" "/usr/lib64" )
# Recursively find all that is needed
loop=1
while [ "$loop" -eq 1 ]; do 
    loop=0
    newDependencies=()
    for library in "${libraries[@]}"; do
        rlink=$(readlink "$library")
        for l in $rlink; do
            for p in  "${paths[@]}"; do
                if [[ ! " ${libraries[@]} " =~ " ${p}/${l} " ]]; then
                    if test -f "${p}/${l}"; then              
                        loop=1
                        newDependencies+=( "${p}/${l}" )
                    fi
                fi
            done
        done
    done
    for i in "${newDependencies[@]}"; do
        libraries+=( "$i" )
    done
done

echo  "Keeping ${libraries[@]}"

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