#!/bin/bash


writefile=$1
writestr=$2


if [ "$#" -ne 2 ]; then
	echo "Error: 2 args required"
	exit 1
fi

dirpath=$(dirname "$writefile")

mkdir -p "$dirpath"

echo "$writestr" > "$writefile"

exit 0 
