#!/bin/bash
#
# LinOTP - the Open Source solution for multi-factor authentication
#
# Copyright (C) 2019-     netgo software GmbH
#
# Run script for packaging tests

set -eu

for service in mysql apache2 postgresql; do
    echo "Starting service $service"
    /etc/init.d/$service start
done

cmd="$*"
echo "$cmd"
$cmd
