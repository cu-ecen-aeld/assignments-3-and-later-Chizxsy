#!/bin/sh

set -e
set -u

# The directory where files will be created
WRITEDIR="/tmp/aeld-data"
# A string to write to the files
WRITESTR="AELD_IS_FUN"

# Clean up previous builds and create a fresh build
make clean
make

# Check if the writer executable was built
if [ ! -x writer ]
then
    echo "ERROR: writer executable not found"
    exit 1
fi

# Create the directory, removing any previous versions
rm -rf ${WRITEDIR}
mkdir -p ${WRITEDIR}

# Check if the directory was created
if [ ! -d ${WRITEDIR} ]
then
    echo "ERROR: Directory ${WRITEDIR} could not be created"
    exit 1
fi

echo "Writing 10 files to ${WRITEDIR}"

# Loop to create 10 files
for i in $(seq 1 10)
do
    ./writer.sh "${WRITEDIR}/file${i}.txt" "${WRITESTR}"
done

# echo "Verifying files..."
# find ${WRITEDIR} -type f | wc -l
# find ${WRITEDIR} -type f -exec grep -H "${WRITESTR}" {} + | wc -l


echo "Test completed successfully"
exit 0
