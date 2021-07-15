#!/bin/bash

####
# microsoft-oms-auditd-plugin
#
# Copyright (c) Microsoft Corporation
#
# All rights reserved. 
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
####

# This script will create a bundle file given an existing kit.
#
# See usage for parameters that must be passed to this script.
#
# We expect this script to run from the BUILD directory (i.e. auoms/build).
# Directory paths are hard-coded for this location.

SOURCE_DIR=`(cd ../installer/bundle; pwd -P)`
BUNDLE_FILE=bundle_skel.sh

# Exit on error
set -e

# Don't display output
set +x

usage()
{
    echo "usage: $0 target-dir intermediate-dir tar-file install-type"
    echo "  where"
    echo "    target-dir is directory path to create shell bundle file (target directory)"
    echo "    intermediate-dir is dir path to intermediate dir (where installer_tmp lives)"
    echo "    tar-file is the name of the tar file that contains the .deb/.rpm files"
    echo "    install-type has the value \"RPM\" for rpm bundle, \"DPKG\" for deb bundle,"
    echo "      empty for the all-inclusive bundle"
    echo
    echo "This script, and the associated bundle skeleton, are intended to work only"
    echo "only on Linux, and only for universal installations. As such, package names"
    echo "are determined via directory lookups."
    exit 1
}

# Validate parameters

DIRECTORY=$1
INTERMEDIATE=$2
TAR_FILE=$3
INSTALL_TYPE=$4

if [ -z "$DIRECTORY" ]; then
    echo "Missing parameter: Target Directory" >&2
    echo ""
    usage
    exit 1
fi

if [ ! -d "$DIRECTORY" ]; then
    echo "Directory \"$DIRECTORY\" does not exist" >&2
    exit 1
fi

if [ -z "$INTERMEDIATE" ]; then
    echo "Missing parameter: Intermediate Directory" >&2
    echo ""
    usage
    exit 1
fi

if [ ! -d "$INTERMEDIATE" ]; then
    echo "Directory \"$INTERMEDIATE\" does not exist" >&2
    exit 1
fi

if [ ! -d "$INTERMEDIATE/installer_tmp" ]; then
    echo "Directory \"$INTERMEDIATE/installer_tmp\" does not exist" >&2
    exit 1
fi

if [ -z "$TAR_FILE" ]; then
    echo "Missing parameter: tar-file" >&2
    echo ""
    usage
    exit 1
fi

if [ ! -f "$INTERMEDIATE/$TAR_FILE" ]; then
    echo "Can't file tar file at location $INTERMEDIATE/$TAR_FILE" >&2
    echo ""
    usage
    exit 1
fi

INTERMEDIATE_DIR=`(cd $INTERMEDIATE; pwd -P)`

cd $INTERMEDIATE

AUOMS_PACKAGE=`ls auoms-[0-9]*.rpm | sed 's/.rpm$//' | tail -1`

# TODO : Add verification to insure all flavors exist

# Determine the output file name
OUTPUT_DIR=`(cd $DIRECTORY; pwd -P)`

# Work from the temporary directory from this point forward
cd $INTERMEDIATE_DIR

# Fetch the bundle skeleton file
cp $SOURCE_DIR/$BUNDLE_FILE .

# See if we can resolve git references for output
# (See if we can find the master project)
TEMP_FILE=/tmp/create_bundle.$$

# Get the git reference hashes in a file
(
cd $SOURCE_DIR/../..
echo "Entering 'OMS-Auditd-Plugin'" > $TEMP_FILE
git rev-parse HEAD >> $TEMP_FILE
cd ../pal
echo "Entering 'pal'" >> $TEMP_FILE
git rev-parse HEAD >> $TEMP_FILE
)

# Change lines like: "Entering 'pal'\n<refhash>" to "pal: <refhash>"
perl -i -pe "s/Entering '([^\n]*)'\n/\$1: /" $TEMP_FILE

# Grab the reference hashes in a variable
SOURCE_REFS=`cat $TEMP_FILE`
rm $TEMP_FILE

# Update the bundle file w/the ref hash (much easier with perl since multi-line)
perl -i -pe "s/-- Source code references --/${SOURCE_REFS}/" $BUNDLE_FILE

# Edit the bundle file for hard-coded values
sed -i "s/TAR_FILE=<TAR_FILE>/TAR_FILE=$TAR_FILE/" $BUNDLE_FILE

sed -i "s/AUOMS_PKG=<AUOMS_PKG>/AUOMS_PKG=$AUOMS_PACKAGE/" $BUNDLE_FILE
sed -i "s/INSTALL_TYPE=<INSTALL_TYPE>/INSTALL_TYPE=$INSTALL_TYPE/" $BUNDLE_FILE

SCRIPT_LEN=`wc -l < $BUNDLE_FILE | sed 's/ //g'`
SCRIPT_LEN_PLUS_ONE="$((SCRIPT_LEN + 1))"

sed -i "s/SCRIPT_LEN=<SCRIPT_LEN>/SCRIPT_LEN=${SCRIPT_LEN}/" $BUNDLE_FILE
sed -i "s/SCRIPT_LEN_PLUS_ONE=<SCRIPT_LEN+1>/SCRIPT_LEN_PLUS_ONE=${SCRIPT_LEN_PLUS_ONE}/" $BUNDLE_FILE

# Build the bundle
BUNDLE_OUTFILE=$OUTPUT_DIR/`echo $TAR_FILE | sed -e "s/.tar//"`.sh
echo "Generating bundle in target named: `basename $BUNDLE_OUTFILE` ..."

gzip -c $INTERMEDIATE/$TAR_FILE | cat $BUNDLE_FILE - > $BUNDLE_OUTFILE
chmod +x $BUNDLE_OUTFILE

# Clean up
rm $BUNDLE_FILE

exit 0
