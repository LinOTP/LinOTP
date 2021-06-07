#!/bin/bash
#
# LinOTP - the Open Source solution for multi-factor authentication
#
# Coypright © 2020- arxes-tolina GmbH
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
