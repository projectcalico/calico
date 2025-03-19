#!/usr/bin/env bash

set -e
set -x

: ${BACKEND:?Error: BACKEND is not set}

FV_DIR="$HOME/$SEMAPHORE_GIT_DIR/process/testing/winfv-cni-plugin/aso"
pushd ${FV_DIR}

# Prepare local files
cp $HOME/$SEMAPHORE_GIT_DIR/cni-plugin/bin/windows/*.exe ./windows

# Run FV.
BACKEND=$BACKEND make run-fv | tee run-fv.log

# Get results and logs
ls -ltr ./report
mkdir /home/semaphore/fv.log
cp run-fv.log /home/semaphore/fv.log
cp ./report/*.log /home/semaphore/fv.log


# Stop for debug
echo "Check for pause file..."
while [ -f /home/semaphore/pause-for-debug ];
do
    echo "#"
    sleep 30
done

# Print relevant snippets from logs
log_regexps='(?<!Decode)Failure|SUCCESS|FV-TEST-START'
compgen -G /home/semaphore/fv.log/*.log > /dev/null && \
for log_file in /home/semaphore/fv.log/*.log; do
    prefix="[$(basename ${log_file})]"
    cat ${log_file} | iconv -f UTF-16 -t UTF-8 | sed 's/\r$//g' | grep --line-buffered --perl ${log_regexps} -B 2 -A 15 | sed 's/.*/'"${prefix}"' &/g'
done;

# Search for the file indicates that the Windows node has completed the FV process
if [ ! -f ./report/done-marker ];
then
    echo "Windows node failed to complete the FV process."
    exit 1
fi

# Search for error code file
if [ -f ./report/error-codes ];
then
    echo "Windows FV returned error(s)."
    exit 1
fi

echo "Run Windows FV is done."
