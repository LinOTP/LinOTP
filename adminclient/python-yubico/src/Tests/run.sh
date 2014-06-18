#!/bin/sh
#
# Run all tests.
#

mydir=`dirname $0`

set -e

: ${PYTHON:="python"}

$PYTHON $mydir/../setup.py test
