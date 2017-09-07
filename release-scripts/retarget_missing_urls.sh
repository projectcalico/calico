#!/bin/bash

# Tests generated URLs to see if they exist. If they do not exist, then emit a comma separated
# list of url fragments to be used as the --url-swap argument to htmlproofer.
#
# Takes the following (required) arguments:
#   --current=v2.6     # the current release stream string
#   --list="x y"       # a space delimited list of URL fragments to test
#   --target=master    # [master] the intended URL to remap to
#   --transport=https  # [https] either http or https
#
# Example:
#   get_url_swap.sh --verbose --current=v2.6 --list='docs.projectcalico.org github.com/projectcalico/calico/tree/master'
#
# if https://docs.projectcalico.org/v2.6 does NOT exist, then emit:
#    docs.projectcalico.org/v2.6:docs.projectcalico/master
#

usage() { echo "Usage: $0 --current=v2.5 --list=<space seperated list> --verbose" 1>&2; exit 1; }

# read the options
TEMP=`getopt -o c:l:p:x:t:v --long current:,list:,target:,transport:,verbose -- "$@"`
eval set -- "$TEMP"

VERBOSE=0
TRANSPORT=https
TARGET_STREAM=master

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        -c|--current)
            CURRENT_STREAM=$2 ; shift 2 ;;
        -t|--target)
            TARGET_STREAM=$2 ; shift 2 ;;
		-l|--list)
		    URL_LIST=$2 ; shift 2 ;;
		-x|--transport)
            TRANSPORT=$2 ; shift 2 ;;
		-v|--verbose)
		    VERBOSE=1 ; shift 1 ;;
        --) shift ; break ;;
        *) usage; exit 1 ;;
    esac
done

if [ $VERBOSE -eq 1 ]; then
	echo "CURRENT_STREAM = $CURRENT_STREAM"
	echo "TARGET_STREAM = $TARGET_STREAM"
	echo "URL_LIST = $URL_LIST"
	echo "TRANSPORT = $TRANSPORT"
fi

# ensure all variables are set
if [ -z ${CURRENT_STREAM+x} ] || [ -z ${TARGET_STREAM+x} ] || [ -z ${URL_LIST+x} ] || [ -z ${TRANSPORT+x} ]; then usage; fi

# Parse each space-separated URL and test for it's existence
URL_ARRAY=($URL_LIST)
for url in "${URL_ARRAY[@]}"; do
	CURRENT_URL=${TRANSPORT}://${url}/${CURRENT_STREAM}
	wget -q --spider ${CURRENT_URL}

	# if we didn't find the URL (i.e. the new version doesn't exist yet ...
	if [ $? -ne 0 ]; then
		REMAP_URLS=${REMAP_URLS},${url}/${CURRENT_STREAM}:${url}/${TARGET_STREAM}
	fi
done

# remove initial comma
REMAP_URLS=`echo $REMAP_URLS | sed 's/^,//g'`

if [ ! -z ${REMAP_URLS} ]; then
    echo --url-swap ${REMAP_URLS}
fi

