#! /bin/sh
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2020 arxes-tolina GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

set -e

if [ -f /etc/linotp/conf.d/softhsm.cfg ]; then
  echo "SoftHSM setup skipped - file already exists"
  exit 0
fi

# The security pin and regular pin can be overriden by passing
# in SOFTHSM_SOPIN and SOFTHSM_PIN
PIN="${SOFTHSM_PIN:-1234}"
SOPIN="${SOFTHSM_SOPIN:-1234}"

# Setup softhsm2 and add config entries to linotp.cfg
softhsm2-util --init-token --free \
    --label "linotp" \
    --so-pin "$SOPIN" \
    --pin "$PIN"

softhsm2-util --show-slots

SLOTID="$(softhsm2-util --show-slots | grep 'Slot' | head -n1 | cut -d' ' -f2)"

for name in config token value; do
  python3 /usr/lib/python3/dist-packages/linotp/lib/security/pkcs11.py \
    -s $SLOTID -p $PIN -n $name
done

# Write the generated configuration into a file which will be read
# when linotp starts.
cat >/etc/linotp/conf.d/softhsm.cfg <<EOF
HSM_PKCS11_CONFIG={
    'module': 'linotp.lib.security.pkcs11.Pkcs11SecurityModule',
    'library': '/usr/lib/softhsm/libsofthsm2.so',
    'password': '$PIN',
    'slotid': ${SLOTID},
    'configLabel': 'config',
    'tokenLabel': 'token',
    'valueLabel': 'value',
    'defaultLabel': 'config',
    'configHandle': None,
    'tokenHandle': None,
    'valueHandle': None,
    'defaultHandle': None,
    'poolsize': 1
}
ACTIVE_SECURITY_MODULE='pkcs11'
EOF

chown -R linotp:softhsm /var/lib/softhsm
