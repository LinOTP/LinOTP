# Bulk enrollment of FIDO2 tokens

## Background

This script/library serves as an example of how to create FIDO2 tokens
in bulk given a list of (LinOTP) user names and realms. The script
will talk CTAP2 to hardware FIDO2 authenticators and associate these
with the tokens in question.

Our script's job is essentially to pretend to be a web browser. We use
LinOTP's `/admin/init` API to generate a FIDO2 token inside LinOTP and
retrieve the information necessary to use a local FIDO2 authenticator
to create a credential. Information about the credential is then sent
back to LinOTP (again using `/admin/init`) to be associated with the
FIDO2 token. The details of this process are governed by appropriate
LinOTP policies, e.g., to set the relying-party ID for the
credential. (One advantage of using a script rather than a web browser
for this is that the browser's origin checking does not factor into
the credential generation, which makes life somewhat easier.)

## Installation

To use the `fido2-enroll` command, do the following:

1. Install the `uv` tool (if you haven't already). See
   https://docs.astral.sh/uv/getting-started/installation/ for
   details.
   
2. Go to the `fido2-enroll` directory (if you're reading this,
   you might already be there).

3. Download the Python extensions required for `fido2-enroll`:

       $ uv sync

   Note that we prefer to get stuff directly from PyPI because the
   packages available in Debian Trixie don't quite cut the mustard.
   For example, the `fido2` package is now up to version 2, and we
   don't want to bother with antiquities such as the obsolete
   `python3-fido2` Debian package in Trixie.

## Use

You can use `uv run fido2-enroll` to launch the script in the virtual
environment that `uv` has set up for it. Alternatively, create a
symbolic link from, e.g., `$HOME/.local/bin/fido2-enroll` to the file
`.venv/bin/fido2-enroll` in the `fido2-enroll` directory:

    $ ln -s $PWD/.venv/bin/fido2-enroll $HOME/.local/bin

This should let you use the `fido2-enroll` command directly (without
the `uv run` in front). Log off and on again if `$HOME/.local/bin`
isn't on your `$PATH` (or put it there manually).

In the simplest case, call the script like

    $ fido2-enroll -B https://linotp.example.com/ foo@bar

(assuming your LinOTP instance is at `https://linotp.example.com/`).
This will create a LinOTP FIDO2 token for the user `foo` in the realm
`bar`, and attempt to add a suitable credential (otherwise known as a
“passkey”) to a FIDO2 authenticator that is connected to your computer
via USB. You will be prompted for the password of the `admin` account
on your LinOTP instance; if your administrator account is called
something different, use the `--admin-user` option to set
`fido2-enroll` right. Chances are that you will also need to provide
the authenticator's PIN, and touch it at the right moment, too, to let
the system know you're there.

It is tedious to have to specify the base URL of your LinOTP instance
all the time. If you add it to the environment like

    $ export FIDO2_ENROLL_BASE_URL=https://linotp.example.com/

then the `-B` option is no longer needed. (We'll just assume that
we've done this from now on out.) If you're using HTTPS to access your
LinOTP instance – as you should – and your LinOTP server's X.509
certificate is using a CA which is not part of the standard root CA
certificate bundle found in `/etc/ssl/certs/ca-certificates.crt`,
you can use the `--ca-file` option to specify a different root CA
file.

You can enroll multiple FIDO2 tokens at the same time using

    $ fido2-enroll foo@bar baz@bar quux@bar

By default, this process will stop after each FIDO2 token to enable
you to switch FIDO2 authenticators (use the `--no-pause` option to
avoid this). Actually, on every token except the first the realm is
optional because the realm given with the first token will be reused,
so the command above is equivalent to

    $ fido2-enroll foo@bar baz quux

or even

    $ fido2-enroll --realm bar foo baz quux

(`--realm` may be abbreviated to `-r`). In point of fact, the command
always remembers the last realm that was explicitly given, so

    $ fido2-enroll --realm bar foo baz@corge quux

will create tokens for `foo@bar`, `baz@corge`, and `quux@corge`. If
your user names all don't have realms and you haven't given a
`--realm` option, `fido2-enroll` will look for the
`FIDO2_ENROLL_REALM` environment variable and use the value of that;
as a last resort, it will prompt interactively for the name of the
realm.

The `--admin-user` (`-U`) and `--admin-password` (`-P`) let you
specify the credentials for an administrator account on your LinOTP
instance. If you'd rather not give the password on the command line
(which we agree would not be the greatest of ideas), you can put the
admin user name and password, separated by a colon, into the
`$HOME/.config/fido2-enroll/admin-credentials` file, which
`fido2-enroll` will read upon startup. Note that your admin user name
cannot contain a colon because that will interfere with parsing the
file; a colon in the password, however, is fine. If you don't like the
default name for the credentials file, you can use the
`--admin-credentials` (`-C`) option to specify a different one, or put
its name into the `FIDO2_ENROLL_ADMIN_CREDENTIALS` environment
variable.

## Library

If you want to enroll LinOTP FIDO2 tokens in your own code, you can
use `fido2-enroll`'s library to do so, as in
```python
from fido2_enroll import enroll_token
```
The `enroll_token` function supports the following parameters:

- `user` (string): The user name for the new FIDO2 token.
- `realm` (string): The realm name for the new FIDO2 token.
- `base_url` (string): The base URL for the LinOTP instance to be used.
- `ca_file` (string): The root CA certificate bundle to be used to verify the
  LinOTP server's X.509 certificate (if any); defaults to
  `/etc/ssl/certs/ca-certificates.crt`.
- `admin_user` and `admin_password` (strings): Credentials to be used on LinOTP.
- `pair` (Boolean): If `True` (the default), attempt to create a
  credential in a FIDO2 authenticator connected by USB and activate
  the FIDO2 token. If `False`, leave the FIDO2 token unactivated.
- `verbose` (Boolean): If `True`, will output progress messages on
  standard output; if `False` (the default), will not do so. Note that
  the function will still prompt the user for the FIDO2 authenticator
  PIN and to interact with the authenticator if required, even if
  `verbose=False`.
- `description` (string): The token description inside LinOTP;
  defaults to `Generated by linotp-fido2-enroll/VERSION` where
  `VERSION` is the version of the `fido2-enroll` package.

Upon success, the function will return the serial number of the newly
enrolled FIDO2 token, or else raise a `fido2_enroll.LinOTPError`
exception. You can inspect the exception instance for more details.
