This directory contains enabled apache configurations for LinOTP

All .conf files in this directory are included from within the LinOTP
VirtualHost in `/etc/apache2/sites-available/linotp2.conf`.

Additional LinOTP components and http based user interfaces link their apache
configurations here with a symlink. To enable / disable those configurations,
create a symlink to the config that should be prefixed with "linotp-" in
`/etc/apache2/conf-available` here.

Only create symlinks in this directory. They must end with ".conf" to be included
from LinOTP.
