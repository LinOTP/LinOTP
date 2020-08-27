# This file contains various functions used by the database scripts

# Load the library as follows:
# . /usr/share/dbconfig-common/scripts/linotp/lib.sh

# Load dbconfig-common configuration
. /etc/dbconfig-common/linotp.conf

LINOTP_CFG=/etc/linotp/linotp.cfg

msg="LinOTP: "

echo_prio() {
  t=$(date +"%Y/%m/%d - %T")
  echo >&2 "$t $1 [linotp postinst] $2"
}
echo_info() {
  echo_prio INFO "$1"
}
echo_warn() {
  echo_prio WARNING "$1"
}
echo_error() {
  echo_prio ERROR "$1"
}
echo_log() {
  echo >&2 "${msg}$1"
}

# escape_login
#
# Prints the RFC 1738 escaped value of
# dbconfig-common user + optional password
#
escape_login() {
  export dbc_dbuser dbc_dbpass
  python3 -c '
from urllib.parse import quote_plus
import os

user = os.environ["dbc_dbuser"]
password = os.environ.get("dbc_dbpass")

loginstring = quote_plus(user)
if password:
    loginstring += ":" + quote_plus(password)
print(loginstring)
  '
}

# configure_sql [sqlalchemy url]
#
# This incorporates previously-determined SQL configuration
# information into the linotp.cfg file.

configure_sql() {
  # Escape hash character for use in sed substitution: # -> \#
  uri="$(echo "$1" | sed  's/#/\#/')"
  sed -i -e "s#^\(SQLALCHEMY_DATABASE_URI\)=.*#\1=\"${uri}\"#" $LINOTP_CFG
  echo_log "SQL configuration in $LINOTP_CFG changed."
}

# init_database
#
# Create and setup required SQL database tables
init_database() {
  echo_log "Initialising database"
  linotp init database
}
