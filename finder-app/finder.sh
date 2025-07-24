#!/bin/sh

filesdir=$1
searchstr=$2

if [ "$#" -ne 2 ]; then
	echo "Error: 2 args required"
	exit 1

fi 


if [ ! -d "$filesdir" ]; then
	echo "Error: $filesdir is not  a valid directory"
	exit 1
fi

x=$(find "$filesdir" -type f | wc -l)

y=$(grep -r "$searchstr" "$filesdir" | wc -l)

echo "The number of files are $x and the number of matching lines are $y"
exit 0

