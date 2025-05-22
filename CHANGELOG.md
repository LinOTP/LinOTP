# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0-dev0] - UNRELEASED

### Added

- unhandled errors are now logged with traceback and returned in the response

### Changed

- `userservice/enroll` now validates otp pins:
  - The `pin` parameter is now required or prohibited based on the `setOTPPIN` policy
  - the provided `pin` is validated against the following policies: `otp_pin_minlength`, `otp_pin_maxlength` and `otp_pin_contents`
- `userservice/enroll` response for HOTP/TOTP tokens now includes a new field: `detail.enrollment_url`, which currently mirrors `detail.googleurl` property
- The `LINOTP_DATABASE_URI` environment variable now requires the PostgreSQL connection URL to use the prefix `postgresql://` instead of `postgres://`

### Security

- The Flask framework used by LinOTP has been upgraded to version 3 to address multiple known vulnerabilities, including CVE-2023-30861.

### Removed

- webprovisionGOOGLE and webprovisionGOOGLEtime policies are removed and migrated to enrollHMAC and enrollTOTP respectively
- OATHTokenSupport config item is removed and "OATH webprovision" is no longer supported in legacy selfservice
- `userservice/webprovision` endpoint is removed

### Deprecated

- The `detail.googleurl` property in the `userservice/enroll` response will be removed in a future major release. Please update your integrations to use `detail.enrollment_url` instead.

### Fixed

- Don't reject empty string as `pin` when `otp_pin_contents=+`

## [3.4.4-rc0] - UNRELEASED

### Fixed

- Reverse the commit that prevented setting the otppin for mOTP tokens
  and used it as token pin instead (was broken since 3.4.1)
- User information was not included in ValidateController responses when
  - the `detail_on_success` policy was active
  - the user had no tokens assigned
  - authentication was successful through a passing policy (e.g., `passthru` or `passOnNoToken`)
  Previously, in this scenario the user object in the response was empty, which could
  impact integrations that rely on the detail_on_success policy, such as LinOTP IdP.
  Now, the user information is correctly included in the response.
- Apply policy `setrealm` in ValidateController when the user is known

### Changed

- Change default JWT session timeout from 15 minutes to 30 minutes

## [3.4.3-1] - 2025-03-05

### Fixed

- timestamp rounding error in challenge signature verifcation when running LinOTP against MySQL 8 database

## [3.4.1-1] - 2025-03-05

### Fixed

- include json-translations in debian package and container

## [3.4.1-1] - 2024-11-27

### Fixed

- actually set Token PIN in `userservice/enroll`

## [3.4.0-1] - 2024-11-12

### Deprecated

- For the container, the `client=` HTTP POST parameter is deprecated and disabled by default.
  It will be removed in an upcoming version of LinOTP. It can be re-enabled
  if the `GET_CLIENT_ADDRESS_FROM_POST_DATA` config is set to a true value
  (the default is "false", for security reasons). Only if re-enabled, the
  "Authorization:" config on the "System config" dialog in the web-based
  management UI is available again and `client=` parameters are looked at.

### Changed

- default of `BACKUP_DIR` is now /var/backups/linotp for the Debian package
- the CLI `linotp backup create` uses `BACKUP_DIR` to save backups instead of the current working directory
- breaking changes to the `linotp audit cleanup` CLI:
  - option `--no-export` is removed
  - option `--export` is added to trigger the export
  - export is disabled by default. Use `linotp audit cleanup --export` to trigger it. This restores LinOTP 2.x behavior
  - options `--min` and `--max` are removed. They are replaced by `--max-entries-to-keep` and `--cleanup-threshold`:
    - `--max-entries-to-keep` (default: 5000) specifies the number of entries to be retained in the audit database.
    - `--cleanup-threshold`: (optional) cleanup is only initiated if the number of entries exceeds this threshold.
      Must be greater than --max-entries-to-keep. No threshold is active by default, i.e. technically speaking,
      this parameter is equal to `--max-entries-to-keep` by default.
- improved debug log output for TOTP resync routine
- improved (mostly by reducing) debug log output during server start and request context.
- reporting api change: If the `realms` parameter is omitted, the realm `/:no realm:/` is now also evaluated.

### Added

- TRUSTED_PROXIES config variable is added to configure LinOTPs proxy trust.
  This config will override (i.e. disable) the trusted forwarding proxy
  configuration in the manage ui -> system configuration.
- add option `--delete-after-days` to `linotp audit cleanup`:
  Delete entries older than the given number of days (starting from the beginning of the day).
  Can't be used alongside `--max-entries-to-keep` or `--cleanup-threshold`!

### Fixed

- when rolling out a forwarding token via /manage, the serial of the target token is included in the description
- faulty JWTs don't cause a `500 Internal Server Error` anymore and the error gets logged properly
- login and logout endpoint for admin authentication was mixed into all `/api/v2` controllers which made
  it possible to use e.g. /api/v2/realms/login. Please use only /admin/<login/logout>
- faulty policies (e.g. `totp_hashlib=sha256`) now return and log a meaningful error message
- audit log entries for `/admin/login` and `admin/logout` now state `success`, `user`, `realm` and `administrator` correctly
- audit log entries for userservice API requests state the correct `success` value
- the last provider (of any kind) can now be deleted
- non-default providers can be now be deleted as expected if and only if they are not part of an authentication policy
- audit log entries for `/userservice/logout` now state `user` and `realm` correctly
- Restored the `period` return attribute in the /reporting/period API endpoint to resolve missing data issue.

## [3.3.3-1] - 2024-09-16

### Fixed

- SMTP now sends e-mails with a "Date:" header to
  accommodate picky SMTP servers on the receiving side

## [3.3.2-1] - 2024-06-19

### Fixed

- migration to 3.0.0 no longer fails (due to missing arg)

## [3.3.1-1] - 2024-06-18

- fix unbound variable in containers `entrypoint.sh`

## [3.3-1] - 2024-06-17

### Changed

- Renamed the following config variables and some changed their defaults:
  - `LOGGING_FILE_LEVEL` -> `LOG_FILE_LEVEL`
    - default: `WARNING` -> `DEBUG`
  - `LOGGING_CONSOLE_LEVEL` -> `LOG_CONSOLE_LEVEL`
    - default: `WARNING` -> `DEBUG`
  - `LOGGING_SQLALCHEMY_LEVEL` -> `LOG_LEVEL_DB_CLIENT`
  - `LOGGING` -> `LOG_CONFIG`
- default of `LOGGING_LEVEL` changed from `INFO` to `WARNING`
- when migrating from LinOTP 2.x, the audit log is no longer truncated to circumvent issues with
  privileges in different database handlers. Old audit log entries that are not truncated now,
  are reported to have a failing signature check because the method has changed with LinOTP version 3.0.

### Deprecated

- In the future config variable `LOGGING_LEVEL` will be replaced by `LOG_LEVEL`.
  `LOG_LEVEL` can and should be used from now on. `LOG_LEVEL` defaults to `WARNING`.

### Added

- new API endpoints to retrieve tokens:
  - `/api/v2/tokens`
    - accepts query parameters `userId` and `resolverName` to filter tokens by
    - accepts query parameter `searchTerm` to filter all other columns
  - `/api/v2/tokens/<serial>`
- new API endpoint to retrieve realms:
  - `/api/v2/realms`
- new API endpoint to retrieve users of a realm:
  - `/api/v2/realms/<realm_name>/users`
    - accepts any field of a user as query parameter to filter by
    - accepts query parameter `searchTerm` to filter users where one field matches the given value
- new API endpoint to retrieve resolvers:
  - `/api/v2/resolvers`
- new API endpoint to retrieve users of a resolver:
  - `/api/v2/resolvers/<resolver_name>/users`
    - accepts any field of a user as query parameter to filter by
    - accepts query parameter `searchTerm` to filter users where one field matches the given value
    - sortable by fields
  - `/api/v2/resolvers/<resolver_name>/users/<user_id>`
    - shows the single user info
- new API endpoint to retrieve AuditLog:
  - `/api/v2/auditlog`
    - accepts most fields of an AuditEntry as query parameter to filter by
- new API endpoint to retrieve all currently reported token statuses:
  - /system/getReportedStatuses
    - accepts query parameter `realms` to filter by realms.
      Use `realms=*` to get all realms including `/:no realm:/`.
- new API endpoint to retrieve context information for manage ui (similar to /userservice/context)
  - /manage/context
- the new API endpoints all return dates in ISO 8601-compliant format
- limit info-box height in manage-ui. Notifications are scrollable, if combined size exceeds newly limited height.
- Server-side invalidation of admin sessions on logout to prevent re-using a JWT after a user dropped its session
- tokens can be imported as disabled tokens
- when triggering a challenge, the token description is returned to help identify the token
- password token now supports the 'onetime' parameter as the former SPASS token type did
- added validation for policy actions. The validation is based on the policy definitions and saving a policy with an invalid action is rejected
- policies detail_on_success and detail_on_fail apply to all /validate endpoints
- /validate endpoints return user information (e.g. given name, phone) when detail_on_success is set
- /userservice/context now returns whether usage timestamp logging is enabled in LinOTP
- improved audit log messages for /admin/ API
- support for MySQL databases that are run with lower_case_table_names=1 (default on Windows)

### Fixed

- Removed: LinOTP no longer supports truncated transaction ids or checking partial transaction id matches
- Upon user logout, admin sessions weren't properly invalidated, allowing to re-use JWTs of logged-out users
- when using pagination, /admin/userlist would not return the last user of the page,
  if the list of users for that page is greater or equal to the value of `rp` (default: 16)
- forward token with an empty pin now supports forwarding to push tokens (was broken since 3.2.4)
- filtering for active/inactive token works correctly
- legacy selfservice qr and push token enrollment breaks with strings in otppin policy
- legacy selfservice customisation not working in login screen
- drop ability to define autoassignment policy with values, it is now only acting as a boolean policy
- an admin could use `reporting/delete_before` for realms they did not have access to
- AdminController and UserserviceController did trigger reporting on unauthorized requests
- AdminController was not triggering reporting for the correct realms in some circumstances
- UserserviceController was not triggering reporting for the correct realms in some circumstances
- requests to userservice API are logging the username in the audit-log instead of the User-Object
- replace deprecated `DATA_DIR` with `CACHE_DIR`. Mako template cache now uses `CACHE_DIR`.
- trim excessive error logging when accessing `/static` files without a valid session

## [3.2.6-1] - 2024-01-31

### Fixed

- show serial and token type in audit log in case of an error; e.g. if a token exceeded its failcounter

## [3.2.5-1] - 2023-11-24

Release 3.2.5 patches a session handling vulnerability in the Self
Service API. This patch is necessary for all versions newer than LinOTP
3.0. We will provide additional details on
<https://linotp.org/linotp-3-2-5.html>.

### Fixed

- Ensure that userservice login results in exactly one session cookie per
  response.
- Avoid a race condition in userservice request method setup which could
  lead to a user being erroneously authenticated as a different user.
- Debian postinst now correctly restarts the LinOTP service again to ensure
  running the latest version without the need for manual intervention.

### Changed

- Use entirely random values for userservice session cookies.

## [3.2.4-1] - 2023-11-15

### Added / Changed

- when using the forward token and a challenge is triggered, the response detail
  contains information about the target token
- forward tokens do not count for license
- the forward token now supports the offline capability of the qr token

### Fixed

- forward token supports forwarding to a qr and push token

## [3.2.3-1] - 2023-02-16

### Fixed

- ensure all types of token will be migrated
- ensure that dbconfig-common triggers the linotp database migration
- Customisation of /manage and /selfservice-legacy was broken due to
  url path changes with LinOTP 3

## [3.2.2-1] - 2022-12-21

### Fixed

- Challenge database is reset once to ensure that Backups pre LinOTP 3
  correctly restore existing challenge-response tokens.
- Migrate encrypted data 'password' with legacy proprietary padding (LinOTP 2.9)
- Fix migration of yubico token to LinOTP 3.2

## [3.2.1-1] - 2022-07-15

### Fixed

- Audit key verification errors solved by using newer version of pycryptodomex.
- Remove weak file permissions in config dir.
- Solved migration of QR-tokens which broke backup-restore from SVA-2.12.5 to SVA-3.0
- Database re-encoding during database migration now also migrates
  managed users that were previously not correctly migrated.
- Debian postinst trying to add admin users via htdigest. This is no longer supported
  and therefore removed. Use the linotp CLI manually instead.
- Ensure that inactive policies are not evaluated. Previously, inactive policies were
  being evaluated in certain situations, leading to wrongly attributed permissions to
  logged-in administrators.

## [3.2-1] - 2022-07-15

### Removed

- The helpdesk controller has been removed.

### Changed

- Apache-based admin authentication is no longer supported.
- Audit Trail export is now ordered descending (latest logs first) when
  done from the Manage-UI.
- Admin authentication: 'Cross site scripting request forgery (CSRF)' is no longer
  handled via the session request parameter. Instead, a CSRF-protection token, which is
  available via cookies, must be sent in the request header. Non-modifying requests
  can be requested via 'GET' and do not need to send the CSRF token. The session parameter
  that was used before should be omitted. API endpoints restricted to accept only via 'POST'
  must use the new header. See the Migration guide for further details.
- Some API endpoints are now restricted to the specific HTTP method which they can be used with.
  Endpoints requiring an admin authentication are now restricted to the POST method if they
  are modifying data. The allowed HTTP methods are highlighted in the API documentation.
- Logging has more configurations now whose config variables are starting by LOG like LOG_FOO. Different
  formatting or log level can be set for the LOG_FILE or the LOG_CONSOLE. Some of the older config
  variables for logging are renamed for consistency.
- Update jQuery and jQuery-Migrate
- The `linotp` package now `Suggests: python3-smpplib`.

### Deprecated

- In the future, all API endpoints will only allow certain HTTP methods. Data-modifying
  endpoints - that are not restricted yet- will only allow POST requests in the future,
  and read-only endpoints will only allow GET requests. The now deprecated HTTP methods
  are also highlighted in the API documentation.

### Fixed

- License limits are now enforced during userservice token enrollment.
- Prevent creating or importing OATH (HOTP, TOTP, Ocra2) tokens with malformatted seeds.
- License monitoring shows license usage for user-based licenses.
- User-based license reporting now filters for date and realm correctly and supports wildcards
  in realm and status.
- In a Debian environment with a MySQL database, it is not anymore required
  to set the charset=utf8 parameter as otherwise, resolvers would not
  correctly display imported users if they contain utf-8 characters.
  Using flask- mysqlalchemy connection solved this problem.
- License exception messages are improved and in case of the user service the
  message suggests asking the system administrator.
- Comprehensive message after importing tokens.
- Adjusted functional_special tests to become regular tests.
- Porting issue for radius token with forwarding transactions.
- Reply to sms challenge with pin+otp.
- User import now always deletes users in the correct managed resolver.
- The linotp support cmd can now install demo licenses.
- The linotp cli commands would not break anymore if localization is involved.
- Resolver names are treated as case-sensitive.
- setConfig is now called from the UI only once to save all parameters in one api call.
- Audit key verification errors solved by using newer version of pycryptodomex.

### Added

- Added grace to license volume exceeding and display accordingly a message
  in the the web ui.
- Added extended information in HOTP/TOTP CSV import UI.
- The CLI now uses a common time format for all backup filenames. The format
  is configurable via config BACKUP_FILE_TIME_FORMAT.
- CLI command `linotp audit cleanup` now writes a backup file of the deleted
  audit entries by default. Export dir defaults to the LinOTP backup dir.
  Exporting can be disabled with a new flag --no-export.
- Added the configuration option for the HttpSmsProvider to define the server
  certificate verification option.
- Added a jwt based admin authentication into LinOTP, so that configuring
  apache to protect admin access to linotp is not needed any more.
  Linotp therefore uses a special realm, the admin realm, which contains the
  resolvers that are allowed to administrate LinOTP. For bootstrapping, an
  internal reserved managed resolver is used for which users could be added via
  the linotp command line tool (s. README.md). The Manage-ui and the
  corresponding interfaces have been extended to indicate if a realm or
  resolver is used for administration.
- Prevent overwriting of the local admin resolver via the user import.
- New linotp admin cli command to set support license, get support info
  and verify the current support status.
- Endpoint delRealm does not cause Error if no realm argument is passed
- Added configuration settings JWT_SECRET_KEY, JWT_SECRET_SALT, and
  JWT_SECRET_ITERATIONS. The latter two control the PBKDF2 function that
  is applied to the default secret (the first key from SECRET_FILE) if
  JWT_SECRET_KEY is not given or is empty. Refer to `linotp config explain`
  for details.
- Email challenge can have a custom message for the user which can be set
  in the config by the EMAIL_CHALLENGE_PROMPT entry.
- Extended sms provider logging
- Added TIMEOUT parameter for all networking providers
- SMS blocking time is now configurable in the SMS token configuration dialog.
  The blocking time (in seconds) is the period that needs to pass before another
  challenge can be triggered by the same user.
- Admin policies now support resolver definition for admin users
- A new API endpoint /manage/context provides context information for logged in
  Manage-UI users.
- Reimplement additional getToken safeguard by defining the settings
  DISABLE_CONTROLLERS and ENABLE_CONTROLLERS - by default the
  DISABLE_CONTROLLERS contains the 'gettoken' controller.
- admin policies now support resolver definition for admin users

## [3.1-1] - 2021-09-30

### Added

- ManageUI policy editor utilizes full window width for improved layout.
- Inform the admin via audit log if there is an challenge integrity error.
- Userservice allows enrollment of HOTP tokens with the webprovisionGOOGLE policy.
- Userservice allows enrollment of TOTP tokens with the webprovisionGOOGLEtime policy.
- RestSMSProvider allows access to nested JSON request data structure items by path.
- Use database config value to enable get_otp feature
- Simplify the HMAC acountname and tokenissuer fallback rules for a more predictable
  behavior in the google authenticator url.
- Token monitoring now better sanitizes the status parameter
- Improved Manage-UI error message if something fails in the initial config
  load phase.
- sqlite can be used as audit database - the response of audit/search
  now skips streaming the response data for sqlite audit databases.
- The server now checks whether the audit table exists or not on start.

### Changed

- Sqlite audit databases can no longer share the same file with LinOTP. If configured
- Audit database timestamp is now ISO 8601 formatted. The timestamp is saved in UTC
  timezone instead of server local time.

### Removed

- No longer support AUDIT_POOL_RECYCLE configuration setting.
  to share the same file, LinOTP will add a suffix to the audit database file name.

### Fixed

- mOTP tokens can now be used in challenge response mode
- Adjust yubico token config text to make it clear that a dedicated
  API key from yubico is required.
- An error message is now shown in the Manage UI if a token import fails
- API /admin/testconnection accepts only the name of an existing resolver as
  parameter. Other parameters are ignored. This fixes the ability to submit
  unauthorized ldap connection requests.
- Manage-UI no longer hangs on failed resolver save requests.
- Token monitoring now correctly counts tokens that are assigned to multiple realms
  only once in mysql and sqlite databases.
- Dynamic user data (e.g. e-mail addresses and phone numbers) are always
  refreshed during resolver lookups triggered by the authentication workflow.
  The policies sms_dynamic_mobile_number, dynamic_email_address, and
  voice_dynamic_mobile_number therefore directly reflect external user data
  changes.
- Remove references to the deactivated newsletter and former company names
- Legacy Selfservice now correctly recognizes type=yubikey tokens in MFA login.
- Manage-UI no longer gets stuck in the interface initialization if the logged
  in user is missing required admin permissions. Now, it is guaranteed that a
  logout is always possible.
- support the assignment of multiple tokens within one request to
  prevent race conditions for example with token_count policies
- getotp view is now working with python3
- Token validity period (stored in UTC) is now compared against current
  time in UTC instead of the server's timezone.
- Log username, realm, serial and token type in audit table when performing a
  `validate/check_status` request.
- Fix padding of encrypted data by migrating to pkcs7 padding
  via the `linotp init database` command.
- Validate no longer wrongly references autoenrollment for users that do
  not own any tokens as the error message.

## [3.0-1] - 2021-06-09

### Added / Changed

- LinOTP is ported from Python 2.7 to Python 3.6.
- LinOTP is ported from Pylons to Flask.
- Use the LinOTP database connection for managed resolvers to allow managed
  resolvers to work with replicated databases and after restores on different
  database connections.
- New Token Selfservice user interface is installed as a recommended
  dependency for "/selfservice". The existing SelfService is deprecated but
  still available under /selfservice-legacy.
- New config value SITE_ROOT_REDIRECT allows to customize the redirect
  path if the user requests the site root path ("/"). If not set, the browser
  is redirected to the legacy selfservice. The new Selfservice will pick
  priority over the deprecated Selfservice if installed.
- Support re-encoding of LinOTP 2 databases from ISO 8859-1 (Latin1) to UTF-8
  via the LinOTP CLI. Latin1 used to be the default for Python 2 against mysql
  but is no longer valid for Python 3.
- Selfservice supports testing tokens after enrollment via the policy
  `verify`. This feature only works in the new Selfservice.
- Selfservice improved handling of expired sessions.
- A new 'linotp' CLI installed on the path provides:
  - admin - administrative commands to manage the linotp application server.
  - audit - administrative commands to manage the audit log.
  - backup - manage database backups.
  - config - configuration file diagnostics.
  - dbsnapshot - Manage system-independent database 'snapshots'.
  - init - key generation and database initialisation/migration.
  - ldap-test - extensive testing of LDAP backends.
  - routes - show the available URL endpoints of LinOTP.
  - run - run a development server.
  - shell - run a shell in the app context.
- Settings can now be configured using environment variables
  `LINOTP_<SETTING_NAME>`.
- Improved config file handling via LINOTP_CFG environment variable:
  - LINOTP_CFG env allows to set a custom search path for config files.
  - `/usr/share/linotp/linotp.cfg` contains distribution default settings.
  - Support for wildcard paths.
  - By default, `/etc/linotp/linotp.cfg` and `/etc/linotp/conf.d/*.cfg` are
    configured for administrator configuration overrides.
  - LINOTP_CFG env treats directory `/foo` like `/foo/*.cfg`.
  - Read config file list from file if `LINOTP_CFG` doesn't exist.
- Support for SoftHSMv2.
- Migration of standalone scripts to linotp CLI subcommands:
  - `linotp-backup` is now available as `linotp backup create`.
  - `linotp-restore` is now available as `linotp backup restore`.
  - `linotp-create-enckey` is now available as `linotp init enc-key`.
- Improved path settings. See DEVELOP.md on how the new options ROOT_DIR,
  CACHE_DIR, DATA_DIR, and LOGFILE_DIR are used and how they are configured by
  default.
- Improved error code separation to differentiate between different problems
  preventing token enrollment.
- The `/userservice/enroll` API now honors default values for hotp and totp
  tokens defined by the following selfservice policies:
  - hmac_otplen, totp_otplen: for the number of digits of an OTP.
  - hmac_hashlib, totp_hashlib: the HMAC hashing algorithm used.
  - totp_timestep: the time stepping for totp tokens.
- Customization of Selfservice information fields via policies:
  - footer_text: Can be used to display e.g. copyright notices.
  - imprint_url: URL to an imprint/ legal notice page.
  - privacy_notice: URL to a privacy notice page.
- LDAP resolver connections to "ldap://" URLs with encryption switched off no
  longer attempt "stealth" encryption behind the user's back with an optional
  fallback to a plain connection. Instead, the encryption state can be
  explicitly controlled. (In the UI, the LDAP resolver dialog now defaults to
  "use STARTTLS" when an "ldap://" URL is specified, but if the user deselects
  this then TLS will not be used at all.)
- LinOTP 3.0 removes all existing audit log entries during automatic database
  migrations because signatures from old audit log entries - written in
  LinOTP 2.x (using Python 2) - can not be validated with python 3.
- Replace unmaintained mysql driver with mysqlclient driver.
- LinOTP no longer works with ISO 8859-1 (Latin1) encoded databases. LinOTP
  provides a migration path if it detects a database that might require
  reencoding.
- LinOTP no longer initializes all required data automatically on startup to
  increase server speed. Instead, the server now only performs a simple
  database check at startup; the `linotp init database` command must be run
  manually if the database check fails. The postinst script will still
  initialize the database though.
- Include README.md in packaging artifacts.
- Ensure configuration files and generated directories are owned by the
  linotp service user.
- Support added to set up linotp with postgres in postinst through migration
  to dbconfig-common for database setup.
- Downgrade mysql dependency to Recommends. The system administrator should
  install the package for their database or allow apt to install recommended
  packages.

### Removed

- Support for Debian versions before buster.
- Apache 2.2 configuration.
- linotp.ini configuration file format.
- non-systemd init script.
- OCRA token.
- Vasco token.
- OSIAM SCIM UserIdResolver.
- The following tools scripts are no longer part of LinOTP:
  - linotp-auth-radius
  - linotp-convert-gemalto
  - linotp-convert-token
  - linotp-convert-xml-to-CSV
  - linotp-create-ad-users
  - linotp-create-auditkeys
  - linotp-create-certificate
  - linotp-create-database
  - linotp-create-pwidresolver-user
  - linotp-create-sqlidresolver-user
  - linotp-decrypt-otpkey
  - linotp-enroll-smstoken
  - linotp-fix-access-rights
  - linotp-pip-update
  - linotp-qrtoken-shell.py
  - linotp-setpins
  - linotp-sql-janitor
  - linotp-token-usage
  - linotp-tokens-used
  - testRadiusChallResponse.sh
  - totp-token
- Predefined yubico apiKey and apiId placeholder values.
- Translations fr, it, es, and zh are removed because of their bad state.
- LinOTP no longer accepts custom LDAP trusted certificates in the
  UserIDREsolver interface. Instead, it now fully relies on the system trusted
  certificates.

### Fixed

- `/gettoken/getotp` now works on tokens that are not in a realm.
- LinOTP legacy Selfservice authorization is now correctly responding with
  an "unauthorized" http response instead of an internal server error.
- After enrollment, Push- and QR-Token enrollment status will stay completed
  even when these tokens are disabled.
- CSV user import now works correctly with files using quote escaping.
- Ensure consistent policy behaviour in all scopes:
  - Specific policies override wildcard policies. This ensures that actions
    can be restricted for a subset of users.
  - Fix quoting of actions such as `sms_text="Hello, your otp='<otp>'"`.
  - All actions are matched for a given user if some of the actions are less
    explicitly defined regarding user and realm fields.
- User based license evaluation now correctly only counts distinct users.
- Translate maxtoken errors correctly.
- Changing the totp time step for an existing token now adjusts the otp
  counter to allow the token to keep working. The otp counter is used to
  prevent replay attacks.
- Unintentional inclusion of file config values in Config database is removed
  to not have security critical information API accessible.

## [2.12.4.dev0-1] - 2021-03-05

### Fixed

- Include Readme.rst in packaging artifacts
- Import User dialog layout fix
- Improve help text output of linotp-create-htdigest script
- No longer deploy obsolete who.ini config file
- Forward tokens support multiple challenges
- HMAC enrollment QR-code correctly URL-encodes tokenissuer
- Tool to import users now enforces system write permission, which is
  required because resolvers are created or updated

## [2.12.3-1] - 2021-04-06

### Added / Changed

- Server: add API /reporting/period to query reporting for a period in a
  range between 'from' and 'to', where the 'from' date is included in the
  range and the 'to' date is not included. The API will search for the last
  repoting entry before the period if no entry for the given period is found.

## [2.12.2-1] - 2021-02-15

### Fixed

- Server: Make rollout token behaviour consistent when used for validate
  workflow (description and cleanup behaviour).

## [2.12.1-1] - 2020-10-23

### Fixed

- Policies: Consistent evaluation of policies is ensured in the "enrollment"
  scope. Evaluation is adjusted to match all actions for a given user if some
  of the actions are less explicitly defined regarding user and realm fields
- Selfservice: MFA login with Push Token and QR Token is correctly processed
- Incorrect max token count evaluation is fixed if a different, more specific
  (not `user:*`) policy with other actions is defined.

## [2.12-1] - 2020-07-28

### Added / Changed

- Server: Expired or wrong cookies in userservice requests will return a
  HTTP 401 (session abort) error
- Server and UI: Add three new columns to the token table:
  LinOtpCreationDate, LinOtpLastAuthSuccess and LinOtpLastAuthMatch; they
  can be viewed under the `admin/show` endpoint, and in the Manage UI
  under TokenInfo; the system settings dialog in the Manage UI provides
  an option to enable and configure their visualisation
- UI: Browser tab icons match the current LinOTP logo
- UI: Browser tab titles start with the name of the web application, to make
  it easier to distinguish between Manage and Selfservice UI in small
  tabs
- UI: Challenge validity time for SMS and email tokens can now be set via the
  Manage UI

### Fixed

- Server: Failed userservice 2nd factor logins increase the fail counter of
  the respective token
- Server: Replication setups on the SVA no longer fail due to faulty
  userservice cookie handling

## [2.11.2-1] - 2020-05-05

### Fixed

- Policy: respect maxtoken policy when creating new token in selfservice frontend
- Selfservice:
  - Cookie expiration date now reflects timezone.
    Closes <https://github.com/LinOTP/LinOTP/issues/136>
  - IE11 Browser rendering fixed, where content height was not respected before.
- Email token: Accept a new challenge as soon as the previous challenge is correctly
  answered. Previously it was not possible before expiration of the
  challenge timeout.

### Changed

- Update LinOTP Apache configuration file to include additional configuration
  supplied by a related package such as the Smart Virtual Appliance

## [2.11.1-1] - 2020-01-30

### Added / Changed

- Server: add support for autoenrollment enrollment notification

### Fixed

- search for tokens with /:no user info:/

## [2.11-1] - 2019-11-12

### Added / Changed

- Server: add api endpoint for helpdesk support
- Server: support for dynamic email address for email token submission

## [2.10.7.2-1] - 2019-11-22

### Fixed

- search for tokens with /:no user info:/

## [2.10.7.1-1] - 2019-10-21

### Fixed

- Server: yubikey token import for otp length 8
- Server: get otp calculation by using utc as base

## [2.10.7-1] - 2019-09-18

- Support for Atlassian’s PBKDF2-based passwords in sqlresolver
- Support for BCrypt based passwords in sqlresolver
- Fix php password support in sqlresolver

## [2.10.6.1-1] - 2019-09-09

### Fixed

- Server: double failcounter increment
- Server: add last access info for tokens which failed to verify

## [2.10.6-1] - 2019-08-21

### Added / Changed

- Server: support ssl/tls and start_tls with emailprovider

## [2.10.5.3-1] Wed, 19 Jun 2019 17:02:31 +0200

- Fix for TOTP replay using auto-resync [CVE-2019-12887] -

## [2.10.5.2-1] - 2019-05-13

### Fixed

- Server: preserve leading zeros of qrtoken offline tan
- Server: minor syntax error in setup.py

## [2.10.5.1-1] - 2019-04-30

### Fixed

- Server: prevent dirty cache if resolver is not available
- Server: resolver and realm cache is wiped when the cache is switched off

## [2.10.4-1] - 2019-02-26

### Added / Changed

- Server: sms provider failover

## [2.10.3.1-1] - 2019-02-13

### Fixed

- Server: using the rollout token outside of the selfservice scope
  should not increment the failcounter

## [2.10.3-1] - 2018-01-25

### Added / Changed

- Server: public release of rollout token

## [2.10.2-1] - 2018-11-21

### Added / Changed

- Server: support for rollout token declaration, so that a token
  can only be used for the selfservice login - the token
  will have the default description 'rollout token'.
  According to the declared policy, the rollout tokens will
  automatically be removed after the first authentication with
  a different token, which will be annotated in the audit log.

### Fixed

- Server: fix the sqlalchemy warnings about unicode conversion
- Server: fix for missing translation function pointer in exception
- Server: fix for passwd files with empty lines

## [2.10.1.4-1] - 2019-01-23

### Fixed

- Server: fix a problem regarding the ldap connection- and response timeouts

## [2.10.1.3-1] - 2019-01-3

### Fixed

- Server: support database migration from any previous version
- Server: fix for yubico verification url to be configurable,
  by default use the new https:// verification urls
  and support connection fallback and blocking

## [2.10.1.2-1] - 2018-11-29

### Added / Changed

- Server: make the pushtoken enrollment more robust for the case that
  the challenge service callback would fail
- Server: support large challenges using blobs

### Fixed

- Server: show up serial and token type in audit log for pushtoken enrollment
- Server: fixes for the initial config handling

## [2.10.1.1-1] - 2018-11-02

### Fixed

- Server: validate/check_status query with user parameter now returns token serial
- Server: Use userid instead of user name to identify open challenges.
  This mitigates the usage of capitals in user names with Active Directory
  as UserIdResolver backend.

## [2.10.1-1] - 2018-10-10

### Added / Changed

- Server: LDAPUserIdResolver failover:
  stay with working LDAP-Servers for an incrementing time
  before retrying the first server
- Server: Add charset/collate clauses to database generation commands:
  ensures compatibility with recent versions of MariaDB
- Server: New policy 'forward_on_no_token' to forward request
  to server if user has no token
- Server: Allow configuration of the challenge prompt via
  system/setConfig?SMS_CHALLENGE_PROMPT=MESSAGE
- Server: New policy 'enforce_smstext' to ignore request param data
- Server: Support to configure HTTP headers in Rest SMS Provider
- API: Show token enrollment status in userservice/usertokenlist
- API: Support check_status without user parameter
- Web UI: Add hint about timezones to manage tokeninfo
- Web UI: Update visuals for manage tokeninfo
- Selfservice Portal: Support optional landing page for selfservice portal
- Selfservice Portal: Show token details in selfservice portal

### Fixed

- Server: Fix LDAPUserIdResolver failover
- Server: Fix RADIUS Forward Token
- Server: Search token list with userPrincipalName
- Server: String 'ignore_pin' instead of '3' is now correctly processed
  for 'otppin' policy action
- Server: LinOTP server now handles forward proxy definition correctly
- Server: Fix storing of timeout tuples within the DefaultPushProvider
- Server: Fix backend for setExpiration UI dialog which failed in some cases
- Server: Provide error message if the setup of a license fails
- Server: Set default time zone to make time-based tokens work in all setups
- Server: Support for SQLUserIdResolvers where the user id is defined as int.
  This fixes actions in the selfservice portal.
- Web UI: Default for splitAtSign is now correctly displayed in the UI

## [2.10.0.10-1] - 2018-09-18

### Fixed

- Fix invalid session cookie in Selfservice

## [2.10.0.9-1] - 2018-07-23

### Fixed

- Fix auto enrollment for SMS token via RADIUS

## [2.10.0.8-1] - 2018-07-17

### Added / Changed

- Support setting http header for e.g. authorization in rest sms provider

## [2.10.0.7-1] - 2018-06-22

### Added / Changed

- policy enforce_smstext to ignore request param data for sms token
  challenge

## [2.10.0.6-1] - 2018-06-07

### Fixed

- Let Push Token handle multiple active challenges
- Policy: Fix index error during wildcard value list evaluation by policy

## [2.10.0.5-1] - 2018-05-24

### Added / Changed

- Add redundant challenge service configuration
- Add new SMS Provider which supports HTTP REST interface

## [2.10.0.4-1] - 2018-03-26

### Fixed

- Use utc time as base for cookie expiration

## [2.10.0.3-1] - 2018-02-22

### Added / Changed

- Move customisation files location (CSS, logos) to /etc/linotp2/custom-style
- Replace crypto/pbkdf2 with more uptodate version
- Add German translations

### Fixed

- Fix /auth/pushtoken test page

## [2.10.0.2-1] - 2018-02-02

### Fixed

- Tools: Fix exception in linotp-token-usage/tokens-used

## [2.10.0.1-1] - 2018-01-30

### Fixed

- Server: Restrict the userservice/context API

## [2.10-1] - 2018-01-12

### Changed

- Adapted for Debian Stretch
- Remove Debian dependency python-socksipy python-repoze.who
- Enhance Push Token (incompatible with previous Push Token version)
- Adjust default TransactionId length to 17
- Enable new policy engine by default
- Moved tokens to new location in src tree
- Removed IE compatibility mode from templates
- Take the already stored mobile number of a token owner (available from
  UserIdResolver) if it exists, otherwise take the number stored in the
  token info
- Refactor dialog button icon generation
- Extract custom form validators into seperate files
- SMSProvider: Moved the SMSProviders to become part of linotp
- UserIdresolver: Moved UserIdresolvers into linotp package

### Removed

- Python packaging: Remove unused smpplib dependency

### Added

- Introduce new token: Voice Token
- Implement explicit-deny for pushtoken
- Add token type specific enrollment limits
- Support loading provider via configuartion in linotp.ini
- Support shorter lost token duration (days, hours, and minutes added)
- Autoassign a token if a request arrives with only username (without
  password)
- Document the otppin policy 3=ignore_pin in the policy UI
- Autoassignment without password
- OATH csv import with sha256 + sha512
- Add Auth Demo pages for challenge-response and push token
  - /auth/challenge-response
  - /auth/pushtoken
- Add expiration dialog for tokens
- Performance improvement by removing mouseover effects on Manage-UI
- Update favicon to follow company rename
- Add UI in manage and selfservice for "static password" token
- Improved Selfservice login with MFA support

### Fixed

- Server: Fix evaluation of forward policy to match most specific
  user definition
- Server: Fix password comparison of password token
- Server: Adjust location of token makos for translation
- Server: Fix typo in getUserFromRequest in case of basic auth
- Server: Fix missing 'serial' for audit and policy check in
  selfservice.enroll
- Server: Fix for loading active token modules
- Server: On LDAP test connection always close dialog
- Server: Fix encoding error that prevented Token View from being displayed
  in the web interface.
- Server: Fix challenge validation to check only one request at a time.
  Prevent (positive) double authentication with the same transaction
  ID and OTP. This used to happen when a user submitted the OTP for a
  transaction ID more than once within a very short timeframe
- Server: Fix for missing LDAP uft-8 conversion
- Server: Fix default hash algorithm. This was causing issues in the YubiKey
  import
- Server: Fix wrong audit log entries where "failcounter exceeded" was
  incorrectly being replaced with "no token found"
- Server: Fix QRToken to use the tan length defined at enrollment
- Server: Fix password and lost token password comparison
- Server: Fix to show deactivated policies in Manage UI again.
- Server: Fix for better user/owner comparison
- Server: Fix to show inactive policies
- Server: Fix import of policies with empty realm
- Server: Verify that only active policies are used
- Server: Fix for policy export to export inactive too
- Server: Fix for target realm handling on token import
- Server: Fix select only active policies for admin policies
- Server: Fix getResolverClassName
- Web UI: Fix UI crash check if backend response is array in ldap
  testconnection
- Selfservice: Fix QR token enrollment and activation

## [2.9.3.3-1] - 2017-09-18

### Fixed

- Server: Fix HMAC-based tokens:
  - prevent (positive) double authentication with the same
    OTP. This used to happen when a user submitted the OTP
    more than once within a very short timeframe.

## [2.9.3.2-1] - 2017-09-07

### Fixed

- Server: Fix YubiKey import
- Server: Give realm parameter priority over user@realm if not
  split@sign

## [2.9.3.1-1] - 2017-08-15

### Added / Changed

- Server: Accept DB2 format database urls

### Fixed

- Policy: Fix support for filtering on `UserIdResolver:` in user field
- Web UI: Simplify user import dialog by removing realm section
- Server: Fix OTP counter for email token
- Server: Remove user related data from logs:
  - Password hash from SQL resolver
  - User information from user.py

## [2.9.3-1] - 2017-07-31

### Added / Changed

- Server: Add support for QR Token unpairing via API
- Server: Support for deleting / disabling token if usage exceeded
- Server: Logging enhancements including unique request IDs and timestamps
- Server: Logging message cleanup to remove unecessary messages
- Server: Support Ocra token with current LinOTP
- Server: Prefer HTTP_X_FORWARDED_HOST to HTTP_HOST for logout_url
- Server: Use HTTP_AUTHORIZATION to determine login name for Basic auth
- Server: Support rfc7239 HTTP_X_FORWARDED_FOR to determine client IP
- Server: Add token issuer to 'otpauth' URLs
- Server: Add FIPS security provider to comply with some operations
- Server: Add experimental new policy engine implementation (off by default)
- Server: Refactor lib.user:
  - changed isEmpty into a property
  - removed methods getRealm, getUser
  - getUserFromParam signature
- Server: Refactor resolvers:
  - setResolver and testresolver
  - configuration handling
- Server: Email provider added support for SMTP port configuration
- Server: Add support for read only (managed) provider configurations

- Web UI: Version static resources to bust browser caching
- Web UI: Add support for importing users via flat CSV file
- Web UI: Add limited support for setting the admin password via the UI
- Web UI: Improvements to LDAP edit dialog

- API: Support dynamic logging via new maintainence controller
- API: Add server healthcheck: maintainence/ok
- API: Support filtering by token type using token_type parameter

- Tools: Add CI Jenkins build pipeline
- Tools: Add central makefile with targets for Docker, packages, tests
- Tools: Add Docker image build infrastructure
- Packaging: Soften hard dependency on libapache2-mod-wsgi
- Packaging: Split auth modules into separate repositories on Github
- Packaging: Move LinOTP client GUI into separate repository on Github
- Config examples: Add example Logstash configuration
- Config examples: Modify logging configuration to prevent duplicate lines

### Fixed

- Server: Fix challenge response authentication (Yubikey)
- Server: Fix enroll of QR Token when username in multiple realms
- Server: Allow utf-8 filenames in FileSMSProvider configuration
- Server: Fix for HSM migration problems
- Server: Fix reusing OTP counter for email token if challenge timed out
- Server: Fix typo in error message

- Web UI: Allow more than 80 characters in user field
- Web UI: Fix filtering in policies tab
- Web UI: Fix parsing of duration configuration fields
- Web UI: Fix link to <https://keyidentity.com>

- API: Add validation of resolver name in defineResolver
- Tools: create-pwidresolver-user: Fix phone fields

## [2.9.1.4-1] - 2017-06-01

### Fixed

- Vasco: Fix token import from file
- Vasco: Fix authentication
- Web UI: Fix error if token configuation dialog is cancelled
- Manage: Remove broken wildcard search using '.' in UserIdResolver searches
- Migration: Fix migration handling routine
- Authentication: Fix behaviour of check_status with empty pass and otppin=2

## [2.9.1.3-1] - 2017-05-04

### Fixed

- Server: Fix realm configuration reset when renaming resolvers

## [2.9.1.2-1] - 2017-04-25

### Fixed

- Server: Fix saving issues with long configuration values

## [2.9.1.1-1] - 2017-04-13

### Fixed

- Server: Fix LDAP configuration issue with long certificates
- Server: Fix empty user list returned by LDAP backend
- Server: Allow unicode characters in provider configuration
- Packaging: Fix openssl installation issue caused by Pre-Depends
  relationship

## [2.9.1-1] - 2017-02-15

### Added / Changed

- Server: New token type: KeyIdentity PushToken
- Server: Add optional caching of resolver lookups
- WebUI: Show welcome and update screens
- WebUI: Add dialog for duplicating resolvers
- WebUI: Better password handling in resolver dialogs
- Reporting: Add paging and CSV output for reporting/show
- API: Use semicolon as CSV column separator by default

### Fixed

- Server: Fix remote token
- Server: Fix evaluating policies for non-existent realms
- API: Don't localize monitoring json output

## [2.9.0.5~rc0-1] - 2016-12-05

### Fixed

- Server: Prefer specific policies over wildcard policies
- WebUI: Reject inequal PINs in set PIN dialogs in addition to the visual
  highlighting
- WebUI: Display certificate in QRToken configuration
- Server: Fix QRToken's CT_AUTH case

## [2.9.0.4-1] - 2016-11-14

### Fixed

- Server: In case of a matching PIN and wrong OTP, increment fail counters of
  PIN-matching tokens only
- Server: Fix maxtoken policy
- Server: Fix import of vasco tokens using transport encoding
- WebUI: Remove policy search bar

## [2.9.0.3-1] - 2016-10-26

### Fixed

- WebUI: Fix realm creation and editing for IE
- Server: Various small QRToken changes
- Server: Fix tokencount handling during assignment

## [2.9.0.2-1] - 2016-09-02

### Fixed

- Server: Fix token enrollment using the API directly after a server restart

## [2.9.0.1-1] - 2016-08-17

### Fixed

- Server: Make constant time comparison compatible with python<=2.7.6

## [2.9-1] - 2016-08-11

### Added / Changed

- Server: Add support for offline authentication
- Server: Add QRToken
- Server: Add forward token
- Server: Add reporting controller
- Server: Add support for multiple providers
- Server: Add support for long config values
- Server: Add issuer label to OATH tokens
- Server: Allow one-time simplepass tokens
- Server: Allow multiple users with same username in one realm
- Server: Support migration of resolvers for assigned tokens
- Server: Add authorization policies for monitoring controller
- Server: Allow named otppin policies ('token_pin', 'password' and 'only_otp')
- WebUI: Slightly polished look and feel

### Fixed

- WebUI: Hide 'Get OTP' button if getotp is deactivated in config
- WebUI: Several bug fixes in different dialogs and elements
- Server: Fix generating transactionids which failed in rare circumstances
- Server: Handle timestamp rounding instead of truncating in MySQL 5.6
- Server: Do not copy old PIN on lost simplepass token
- Packaging: Remove debconf entry 'linotp/generate_enckey'
- WebUI: Validate resolver configuration on resolver definition
- WebUI: In realms dialog, alert if no resolver selected

## [2.8.1.4-1] - 2016-08-05

### Fixed

- WebUI: Fix setting token realm

## [2.8.1.3-1] - 2016-07-29

### Fixed

- Server: Fix pin handling in email token

## [2.8.1.2-1] - 2016-06-10

### Added / Changed

- Server: Add support for demo licenses

### Fixed

- Selfservice: Fix setting tokenlabels
- Server: Set the first created realm as default realm
- Server: Fix admin/show using a serial number and an active admin policy
  containing a wildcard
- Server: Fix import of policies missing scope or action
- Server: Fix license import using IE

## [2.8.1.1-1] - 2016-04-08

### Fixed

- Server: Fix license decline under certain conditions

## [2.8.1-1] - 2016-03-24

### Added / Changed

- Server: Add monitoring controller
- Server: Add support for encryption migration (HSM)
- Server: Add 'forward to server' policy
- Server: Extended user filter in policies
- Server: Reduce number of userid authentication calls
- Server: Enable less services in default configuration
- Server: Add French, Italian, Spanish and Chinese translations
- WebUI: Various cosmetic fixes
- WebUI: Update jQuery, jQuery UI and jed

### Fixed

- Server: Fix forwarding policy when parameter list is empty
- Selfservice: Fix access to userservice with UTF-8 characters
- Selfservice: Fix resolver user wildcard support in extended policy user def
- WebUI: IE11: Deliver requested language
- WebUI: Support for IE11 logout and cookie deletion

## [2.8.0.3-1] - 2016-02-05

### Fixed

- Server: Increment 'failCount' even if maxFailCount is reached
- Server: Fix TOTP tokens with empty timeshift values
- Server: Fix export of empty token list
- Server: Fix policy view showing only realm specific policies
- Server: Fix token settings saving for TOTP and OCRA2 tokens

## [2.8.0.2-1] - 2015-12-17

### Fixed

- Server: Fix for double escaping when using info_box
- Server: Fix for information disclosure with audit search
- Server: Prevent enumeration/information leakage in validate/check
- Server: Remove session id from URL
- WebUI: Clear PIN input fields on closing the 'Set PIN' dialog
- Selfservice: Enforce session and cookie check in all userservice actions
- Selfservice: Add missing session invalidation on selfservice logout
- Config examples: Set security relevant headers in example apache config
  files
- Config examples: Set X-Permitted-Cross-Domain-Policies header in example
  Apache config files

## [2.8.0.1-1] - 2015-11-30

### Added / Changed

- Server: Add support for `*` wildcard in policy client definition
- Server: Add support to set random pin on token import

## [2.8-1] - 2015-11-25

### Added / Changed

- Server: Add FIDO U2F support
- Selfservice: Enroll FIDO U2F, e-mail and SMS tokens
- Server: Losttoken: Support enrollment of e-mail and SMS tokens
- Server: Trigger challenges for multiple challenge-response tokens with one
  request
- Server: Support deleting multiple policies with one request
- Server: Rework and improve token counter logic
- Server: Add policy actions 'emailtext' and 'emailsubject' in scope
  'authentication' to define body and subject of e-mails sent by e-mail
  tokens
- Server: Add parameter to define SMS messages sent by SMS tokens
- Server: Add support for defining multiple OCRA2 callback URLs
- Server: Add optional ability to save last_accessed timestamps for tokens
- Server: Add crypto migration controller to change in-use cryptographic
  techniques, switch to HSMs or replace in-use HSMs
- Server: Add support for using UserPrincipalName as username
- Server: Support wildcard `*` for serial number filter in admin/show
- Tools: linotp-auth-radius: Support for unicode radius requests
- Selfservice: Support yubikey tokens with public_uid
- Server: Add target realm input for token imports
- Server: Prevent accidental admin lock-out using read-only admin policies
- Server: Support autoassignment policy without action value

### Fixed

- Selfservice: Fix getSerialByOtp functionality for yubikey tokens
- Server: Fix importing yubikey tokens without prefix
- Server: Fix autoassignment with remote token pointing at yubikey token
- Server: Fix autoassignment using tokens with different OTP lengths
- Server: Prevent counter increments of inactive tokens
- Server: Don't return counter parameter on TOTP enrollment
- Selfservice: Fix occasional login problems using non-ASCII characters
- Server: Fix occasional problems sorting userlist with unicode characters
- Server: Fix usage of otppin policy for remotetoken with local pincheck
- Server: Don't return error messages on unconfigured autoenrollment
- Server: Always set OTP length in remote token enrollment
- Server: Don't return error messages for policy otppin=1 and unassigned
  tokens
- Server: Reply to OCRA2 challenge providing only transactionid and OTP
- WebUI: Don't show dialog asking for realm creation if no useridresolver is
  configured
- WebUI: Fix WebUI for recent Internet Explorer versions
- WebUI: Clear key and PIN input fields after token enrollment
- Tools: linotp-create-pwidresolver-user: Fix duplicate and ignored
  command-line arguments
- Tools: Correctly package linotp-enroll-smstoken tool
- Tools: Use Digest instead of Basic Authentication in
  linotp-enroll-smstoken
- Tools: Display an error message in linotp-enroll-smstoken when
  dependencies are missing
- Tools: Fix linotp-sql-janitor crash when executed without --export option
- Server: Fix for wildcard search with available unassigned tokens
- Server: Fix LinOTP on pylons 0.9.7
- Packaging: Remove nose dependency from linotp install process

## [2.7.2.2-1] - 2015-11-12

- Fix XSS vulnerabilities in manage WebUI

## [2.7.2.1-1] - 2015-07-08

### Fixed

- Server: Token in autoassignment were assigned randomly instead of the one
  that actually matched the OTP value
- Server: When using check_s the realm context was not correctly set. If the
  token is in a realm, that realm should be used not the default realm
- Server: Uninitialized variables in remotetoken in case of connection error
- Server: Always set random PIN during token enroll/assign if the
  corresponding random PIN policy is set
- Packaging: If a2dissite linotp2 is unsuccessful during package removal the
  uninstallation broke off. Now errors with 'a2dissite' are printed to
  stderr during installation/removal but don't break the scripts
- Packaging: Add SQLAlchemy<=0.9.99 dependency due to 'SQLAlchemy Migrate'
- Packaging: Fix for LinOTP installation in a LSE Smart Virtual Appliance on
  Debian Jessie. Since MySQL lacks a systemd service file use polling to
  check when MySQL is brought up
- Server: Fix erroneous reply message about 'unconfigured autoenrollment'
- Server: Fix for enrolling tokens via the selfservice webprovision with
  random pin policy set
- Packaging: Allow WebOb version 1.4 in debian 8 (jessie)
- Server: Fix for handling users with @ in name (principal name) in
  selfservice access
- WebUI: Fix for selfservice (Internet Explorer caches GET requests)
- Server: Fix extended search in Audit Trail

## [2.7.2-1~precise] - 2015-03-25

### Added / Changed

- Server: Auto enrollment - enroll an email or sms token if user has no
  token and authentication with password was correct
- Server: Support 'now()' in LDAP search expressions
- Selfservice: Split Selfservice into userservice controller and selfservice
  renderer to support remote selfservice interface
- WebUI: SQL and LDAP resolver mapping validation (needs to be valid JSON)
- WebUI: E-mail and SMS provider definition validation (needs to be valid
  JSON)
- Packaging: Support for Ubuntu 14.04 (with Apache 2.4)
- Packaging/Server: Support for Pylons 1.0.1
- Packaging: Internal package refactorization to unify structure and version
  number handling
- Packaging: Apache linotp2 VirtualHost will no longer be overwritten during
  Debian package upgrade. VirtualHost example files are copied to the same
  location where the LinOTP package is installed and only afterwards it is
  moved to /etc/apache2 (if it does not exist already)
- Packaging: Cleaned up and hardened Apache linotp2 VirtualHost files
- Tools: Improved linotp-create-pwidresolver-user and
  linotp-create-sqliddresolver-user to to generates more secure passwords
- Tools: Added tool to massenroll SMS token

### Fixed

- Server: Fixed support of old licenses, where the expiry is in the date
  entry
- Server: Fixed error during token unassign (because of setPin call)
- Server: Fixed searching for a user in multiple realms
- Server: Fixed exact search for user in tokenlist
- Server: Fixed sorting of userlist with unicode
- Selfservice: Fixed selfservice history browsing

## [2.7.1.2-1~precise] - 2015-02-13

### Added

- enhanced password genenerating tool to generate more secure passwords
  entries for usage via passwd and sql resolvers
- added ui hints for the sms and email token config
- use radius token config defaults for radius token enrollment
- use remote token config defaults for remote token enrollment
- adjust the copyright date from 2014 to 2015

### Fixed

- searching for unknown users in tokenview, showed all tokens that had no
  user assigned.
- audit query with empty arguments fixed
- made selfservice history browsing working again

## [2.7.1.1-1~precise] - 2015-01-21

- Bug Fix: Don't ignore whitespace in license file when calculating signature

## [2.7.1-1~precise] - 2014-12-12

### Added / Changed

- Server: Added check for optional support and subscription license
- WebUI: Show warnings when the support and subscription has expired or
  number of supported tokens has been exceeded
- WebUI: Editing the token config in the WebUI will only save what has been edited
- WebUI: PIN setting is now part of the 'enroll' dialog instead of being in a
  separate dialog
- WebUI: Don't allow setting the token PIN in the token enrollment dialog when the
  'random_pin' policy is set
- WebUI/Server: Added translation of selfservice and policy messages
- WebUI: Enabled JavaScript localisation (jed based) for 'manage' and
  'selfservice' UI
- Server: Added Yubikey token support for uppercase OTP values
- Server: Added support for Yubikey token resync
- WebUI: Info and error boxes in the 'manage' UI now stack instead of
  overlaying (hiding the older ones). When displaying more than one box a
  'Close all' link is shown
- WebUI: Improve CSS styling for info and error boxes in 'manage' UI
- WebUI: Adapted the 'selfservice' and 'auth' interfaces to the 'manage' UI style
- WebUI: Improved display of currently selected user and token
- WebUI: Restricted the selection to a single user
- Server: Added system/getPolicy support for 'user' as filter criteria
- Server: Added system/getPolicy support for 'action' as filter criteria
- WebUI: Preset LDAPUserIdResolver AD with objectGUID instead of DN
- WebUI: Rework the selfservice Google web provisioning to refer to FreeOTP
  and other softokens as well
- Server: Include OTP length and hash algorithm used in the 'otpauth' URL
  generated when enrolling HOTP or TOTP tokens
- WebUI: Display the generated seed in the enrollment tabs in a copyable form
- WebUI: Extendend the eToken dat import to display start date support with hh:mm:ss
- Server: Added configuration options to selectively disable parts of LinOTP
  (manage, selfservice, validate)
- WebUI: Added 'clear' button to policy form
- WebUI: Made policies 'active' by default
- Server: Initialize repoze.who with a random secret during server startup
  or restart (old 'selfservice' sessions become invalidated)
- Server/Tools: Added the ability to dump the audit data before deletion
- Packaging: Removed obsolete SQLAlchemy <0.8.0b2 restriction
- Server: Random generation: switched to more secure randrange and choice methods
- WebUI: Updated jQuery to v1.11.1 and all plugins and JS libraries
  (Superfish, jQuery Cookie, jQuery Validation, ...) to their latest version
- WebUI: Simplified selfservice tokenlist handling
- WebUI: Added warning to auth forms when Javascript is disabled in the
  browser
- WebUI: Improved auth form handling of JS errors
- Server: Removed deprecated /auth/requestsms form because SMS can be
  requested using the regular /auth/index form (by doing challenge-response)

### Fixed

- Packaging: Fixed ask_createdb debconf question that kept being asked on
  upgrade of the Debian packages
- WebUI: Cleaned up selfservice mOTP Token enrollment
- WebUI: Some fixes for localisation and wrong validation of seed input field
- Server: Fixed the search for ee-resolver tokens and user
- Server: Raise exception for empty 'user' in 'system' or 'admin' policy
- Server: Load the HSM before the LinOTP config, so that the config can hold decrypted values
- Server: Fixed help_url to always use linotp.org site with version
- Server: Added support for migrating old linotpee resolvers entries
- Server: Fixed reinitialisation of Yubikey token
- Server: Yubikey checkOtp should not raise exception if the OTP is too short
- Server: Fixed bug in Yubikey CSV import
- Server: Fixed padding and unpadding code for PKCS11 module
- Server: Fixed padding and unpadding code for YubiHSM module
- Server: Added LinOTP config options 'pkcs11.accept_invalid_padding' and
  'yubihsm.accept_invalid_padding'
- Server: Fixed token import to support ocra2 token
- WebUI: Fixed small display error when deleting or modifying multiple
  tokens in the 'manage' UI
- WebUI: Fixed selfservice enroll of mOTP token
- Server: Fixed token serial not appearing in the audit log in some cases

## [2.7.0.2-1~precise] - 2014-07-31

- Fixed PSKC import with plain input
- Fixed SecretObj cleanup in some corner-cases
- Cleaned up default parameters in functions to prevent memory leaks
- Added late binding to ORM mapping
- Fixed several issues with Oracle databases such as: reserved words in
  columns, None/empty values not being mapped correctly to Python objects,
  Unicode handling
- Made significant modifications to SQLAudit to fix a memory leak
- Fixed checkPolicyPost() in admin/init without serial (#12603)
- Added /:no realm:/ search option for token list
- Removed empty token config tabs in the WebUI (#12634)
- Added linotpAudit.error_on_truncation config option to control DB
  behaviour when writing large values to the DB

## [2.7-1~precise] - 2014-05-20

- Integrated linotp-ee package into this package, adding:
  - Support for SQL Audit
  - Tools such as: linotp-decrypt-otpkey, linotp-tokens-used, linotp-backup,
    linotp-restore, etc.
  - Support for HSM
  - eTokenDat, PSKC, DPWplain and vasco token import
- Fixed broken custom-template handling (#12555)
- Fixed some corner cases of JSON and CSV audit output (#12550, #12556)
- Fixed erroneous QR-Code generation
- Pinned WebOb version to < 1.4 due to incompatibility with Pylons (#12586)
- WebUI: Moved 'License' menu entry to 'Help/Support'
- WebUI: Added 'Help/About' dialog
- WebUI: Cleaned up a little and exchanged the LinOTP logos

## [2.6.1.1-1] - 2014-04-08

- Fixed Yubikey token so it supports LinOTP/RADIUS challenge-response
- Removed 'const' JS variable that broke IE9
- Added Yubikey public ID to token description when importing CSV file
  (#12417)
- Fixed erroneous active-token-count in WebUI (#12523)

## [2.6.1-1] - 2014-03-27

- Added support for BasicAuthentication to HttpSMSProvider
- Prevent resolver creation with same name (and different case)
- Improved /auth/index forms and deprecated /auth/requestsms
- Improve entropy by using /dev/urandom (#12243)
- Added streaming output to audit/search JSON and CSV (#12392)
- Made wildcard search in SQL Resolver more precise (#12135)
- Small graphical WebUI fixes (#12229)
- Added possibility to change the phone number of SMS token (#2953)
- Require `*` for wildcard token search (#2838)
- Removed PIL as a hard dependency (you may use pillow-pil) (#12409)
- Only enable apache site on first installation (not upgrade) (#12246,
  #12457)
- Supress error during installation if no 'lse_release' exists #(12237)
- Shorten UserIdResolver display string in UserView (#2678)
- Added python-httplib2 dependency
- Added challenge-response and http-POST to remote token (#12433, #12451)
- Added challenge-response to RADIUS token (#12432)
- Added client information to audit log (#12417)
- Enable 'Enter' key in auth/index forms (#12103, #12446)
- Allow SmtpSMSProvider to raise exceptions (#12419)
- Several challenge-response error handling fixes (#12416, #12420, #12427)
- Several OpenID fixes (#12415, #12428, #12265, #12190, #12264)
- Fix hostname/port FQDN splitting (#12410)
- Added man page for linotp-auth-radius
- Removed obsolete log warnings and errors (#12396, #12443)
- Prevent challenges from being sent when multiple tokens match (#12413)
- Fixed check_yubikey so that it supports two slots (#12477)
- Enabled realm assignment during Yubikey enrollment
- Added autoassignment for Yubikeys
- Added new policy 'ignore_autoassignment_pin'
- Removed newlines in token CSV export (#12465)

## [2.6.0.3-1] - 2014-02-19

- Fix problem with LDAPS connection (#12431)
- Catch token exceptions to prevent errors when processing several tokens (#12416)

## [2.6.0.2-1] - 2014-02-14

- Fixed the module exception in community edition. (#12424)

## [2.6.0.1-2] - 2014-02-11

- Fixed the ownership of /etc/linotp2/private.pem

## [2.6.0.1-1] - 2014-02-07

- Added radius client tool "linotp-auth-radius", which supports challenge response
- Fix the otppin=2 (no pin) problems with email and totptoken (#12399 #12398)
- Fix for email token to support otppin=2 (closes #12398)
- Fix 'Logout' button (closes #12371)

## [2.6-1] - 2013-12-23

- Added Challenge Response functionality for all tokens.
- Added Challenge Response Policy (#12234)
- Searching for tokens in the WebUI now uses wildcards.
  - To find benjamin you will have to search for `ben*`.
  - "ben" will return nothing.
- Added UserPassOnNoToken Policy (#12145)
- Export token list to csv (#2963)
- Add additional user attributes in the token list api (#12187)
- Export audit list to csv (#2963)
- Added /auth/index3 with 3 lines (#12138)
- Use Yubikey with prefix like the serial number (#12039)
- Enroll Yubikey with Challenge Response and Yubikey NEO (#12186)
- SMS-Token: The mobile number can now be used in the mailto field (#12151)
- Add non-blocking behaviour when sending SMS OTP (#2986)
- The token description can be set in the WebUI (#12163)
- The Resolver dialog now start the realm dialog if no realm is defined (#12160)
- The yubikey in Yubivo mode (with 44 characters output) is supported (#2989)
- Import Yubico CSV in Yubico mode for Yubikeys, that were generated with the
  Yubico personalization tool (#12326)
- The token type list is sorted when enrolling in the management WebUI (#12231)
- The authorize policies can contain regular expressions for the token
  serial number (#12197)
- Added script 'linotp-token-usage' for token statistics (#12299)
- Added severals cripts for simpler installation and maintenance:
  - linotp-create-certificate, linotp-create-enckey, linotp-create-auditkeys,
  - linotp-fix-access-rights (#2883)
- /validate/check can return addition token details of the authenticated token.
  - Configured by the policy 'detail_on_success' (#2661)
- Support for eToken dat file import (#12124)
- Policies can now be deactivated and activated (#2903)
- Added new token type E-mail token, that sends OTP via smtp (#2704, #12332)
- Improve pam_linotp for build process and challenge response support (#12176)
- Using POST instead of GET requests in selfservice UI (#12161)
- Improved the HTML online help, to be available online from linotp.org
  or installed on the server
- Removed several misleading error messages during installation
- Improved several error messages
- rlm_linotp now also builds on Ubuntu 12.04 (#12154)
- Improved the certificate handling for the LDAP resolver (#12089)
- Improved the performance when loading many users in the WebUI (#12076)
- Fixed a padding problem in the OCRA token (#12202)
- Fixed the logout link in the management Web UI (#12022)
- Fixed SMS token without serial number (#12322)
- Fixed the signature checking in the SQL audit module (#12267, #2700)
- Fixed apache config to use secure cookies (#12148)

## [2.5.2.1-1] - 2013-08-02

- Change RC8 to the release version

## [2.5.2-1.rc8] - 2013-07-12

- Fixed multiple selected policies #12114
- Fixed for user with special char for access to selfservice #12110
- Fixed export of policy with user with special chars #12107
- Fixed of missing manpage for source distribution #12100
- Fixed export of empty policies #12099
- Fixed of weird PKG-INFO from build #12098
- Fixed for ad users with special char in dn for access to selfservice #12090

## [2.5.2-1.rc7] - 2013-07-08

- Fixed ignored timeStep from enrollment dialog #12080
- Fixed access for AD user with special characters to selfservice #12090
- Added required package entry for configobj in glinotpadm #12088

## [2.5.2-1] - 2013-07-05

- release community edition

## [2.5.2-0.rc6] - 2013-07-04

- Fixed wrong positiv response during OCRA rollout #12058
- Fixed enrolling Yubikeys in GTK client #12070
- Fixed default getFromConfig #12067
- Added index to token table #12061
- Fixed documentation #12075
- Added more unittests
- Fixed OCRAChallengeTimeout #12069
- Fixed the UI of the TOTP enrollment to honour the timestep #12080
- Fixed the dependency for repoze.who #12081
- Added multiple LDAPS useridresolvers #12065

## [2.5.2-0.rc5] - 2013-07-02

- fixed LDAP encoding (#12062)
- fixed tokenclass type (#12054)

## [2.5.2-0.rc4] - 2013-06-28

- fixed unicode in LDAP-Resolver
- fixed JSON object handling in webUI

## [2.5.2-0.rc3] - 2013-06-26

- Bug #12026 Closed (fixed) WebUI: SyncWindows and CounterWindow could not be set
- Bug #12018 Closed (fixed) otplen is not honoured by /admin/init
- Bug #12015 Closed (fixed) Hide help button in CE
- Bug #12014 Closed (fixed) LinOTP Logo
- Bug #12011 Closed (fixed) Typos in translation
- Bug #3003, #3000 Closed (fixed) Wrong wsgi file in documentation
- Bug #3002 Closed (fixed) Added info for creating certificates
- Bug #2999, #2998, #2996, #2995, #2994, #2992, #2991 Closed (fixed) Improved documentation for manual installation
- Bug #2975 Closed (fixed) removed link to linotp-register
- Bug #2969 Closed (fixed) rewrite string handling in logging
- Enhancement #2909 Closed (fixed) Better handling of HSM errors
- Bug Closed #2864 (fixed) Tokenrealm does not work with sqlite

## [2.5.2-0.rc2] - 2013-06-19

- fixed #998

## [2.5.2-0.rc1] - 2013-06-02

- added possibility to display action history in selfservice
- added a script (linotp-pip-update) to update a pip installation (#882)
- added authentication to ocra controller (#873)
- added dynamic selfservice actions
- added feitian library, that can create the feitian challenge
- added hook for setup defaults in the manage enrolment gui (#925)
- added label for enrollmen of OCRA token
- added labels into selfservice UI (#842)
- added labels tags to html UI for better usage (#842)
- added missing vasco token
- added policy import to WebUI (#858)
- added policy support for dynamic tokens
- added several tools (#883) to make the installation like pip install easier.
- added the dynamic hmac and sms token implementation + rendering
- added the dynamic motp token
- added the dynamic version of the totp token
- added the possiblity to export the policies in the WebUI and in the GTK client (part of #774 and #858).
- added the user and realm to the enrollment of dynamic tokens.
- added transition packages to rename the debian archives (#844)
- added users and resolvers to policies in selfservice, authentication, enrollment and authorization (#856). cool!
- added WebUI and Doku for #872: The policy checker
- added yubikey in orignial yubikey mode (44 characters) to authenticate with the yubico online cloud service
- add missing genkey in the ocra selfservice
- add the policy definitions of the dynamic tokens
- assign Token by OTP value (#666): Added to selfservice
- closed #895: More detailed information when the SMS is sent via /validate/check of /validate/smspin.
- closed #924 and #942: The preset of the mobile number for an SMS token is now contained in the token.mako file.
- closed #932: The user was not able to authenticate to selfservice
- closed #935: Deprecation Information about searching tokens
- closed #938: Use SecureFormatter in linotp.ini
- closed #939: The sms text from the policy is used to send the sms
- closed #947: We require python 2.6.
- closed #950: added dependency for python repoze.who
- closed #952: make sure that genkey is in defined range
- correct audit entry, when the userpassword (otppin=1) is wrong. (#843)
- dynamic PASSWORD token
- dynamic RADIUS token
- dynamic Remote token
- dynamic token
- extended the template lookup path to support dynamic token definitions
- first implementation for #871 to support feitian c601 token.
- fix #874 and provide the documentation statically.
- fix and test for ticket #864 - sqlite: assign realms to token
- fixed #737 and added a search button to flexigrid.
- fixed #875: added SecureFormatter to be able to remove non printable characters from the log args
- fixed #876: the redirect will only be done, if the login was successful.
- fixed #879: The audit trail does not show entries with sqlalchemy 0.8.0
- fixed (#890): The setting of the OCRA PIN does not work in the WebUI.
- fixed #893: We added more tests for the HttpSMSProvider.
- fixed #898: The CA certificate from the LDAP Resolvers gets written only on the first request.
- fixed #911, use a default token list if linotpTokenModules is not defined.
- fixed #931: If the useridresolveree is not present or the LDAP or SQL resolver can not be loaded, we now added an error message.
- fixed #948: return space instead of empty string in case of MS SQL server
- fixed #954: problems with redundant MS SQL server.
- fixed an issue with userassign and added policy tests. (#863)
- fixed missing dependency for configobj (#888)
- fixed missing urllib import for ocra token.
- fixed problem, that an admin was not able to view the users in the realm he has rights to
- fixed the broken FileAudit module
- fixed the possiblity to do cross site scripting in the doc controller.
- fixed user enumeration with validate/smsping (#869)
- fix for #923 - delete of undefined tokentype object
- fix for #933 - restore noreferrals status
- fix for #940 hmac vaerification + more debug token info
- fix for #945: You may either specify genkey or otpkey but not both
- fix for defaultRealm() in ocra/check_t (value instead of function)
- fix for encoding problem in qr image #930
- fix for SQLAlchemy unicode warning
- fix for ticket #920 - put request identifier in the log output
- fix for tokeniterator exact user match
- fix permissions for SSL privkey and who.ini (#A756)
- fix problem #848: The system settings are not stored, it data on another tab is missing.
- fix the counter reset in case of the model setType() call
- fix the OCRA bug for missing leading zeros - truncation to last digit
- implemented additional API to to a get_serial_by_otp in selfservice (#666)
- implemented (with tests) the controller /system/checkPolicy (#872)
- improved #679, the usage of clients in policies: exclude clients
- improved PSKC import to import OCRA suites (#823)
- increase font size (style italic) to make it easier to assign a token to a user...
- integration test adjustments for py2.6
- limit size of realm and resolver dialogs. If hundret resolvers or realms are defined, the dialog is too big
- make it easy installable on Univention Corporate Server.
- make the cookie a secure cookie, means it must be transferred via SSL
- migrated Vasco token (#927)
- migrate simple pass token and tagespasswort to dynamic token module
- moved etoken enrollment tool from server to EE client (#834)
- performance fix - reduce userid lookup
- renamed the webprovissionOCRA to activateQR #912
- resolver init hook - #941
- reverted to the timeStepping=30 for the setup
- set maximum auth count and validity period. (#743)
- solve 2.6. compatibilty issue for time2float
- the mobile number (instead of phone) will now be used in selfservice for SMS token

## [2.5.1-1] - 2013-02-22

- fix in WebUI for System settings and IE compatiblity
- fixed tokenview in selfservice (#852)
- Work in Progress for release 2.5.1
- improved python PIP installation
- Define the contents of the lost password token (#806)
- Only active tokens are counted for the licensing (#810)
- Fixed translation
- Added alert-box (pop under)
- Improved performance with dynamic token classes
- added QR-Code image to reply
- added QR-Code enrollment in management web UI and selfserivce portal
- added online help/manual
- acced import OCRA seeds via CSV
- Possibility to send 500er HTTP error instead of status:false
- fixed broken totp resync

## [2.5.0-9] - 2012-12-17

- fixed location of config files

## [2.5.0-8] - 2012-12-12

- TOTP token now honours defaultOtpLength
- fixed TOTP accept second OTP

## [2.5.0-7] - 2012-12-03

- change to encrypt data by label not handle

## [2.5.0-6] - 2012-11-22

- fixed the possibility to have more than one slot connected in pkcs11 security provider

## [2.5.0-5] - 2012-11-22

- fixed ocra resync

## [2.5.0-4] - 2012-11-21

- fix log output in case of missing sha224

## [2.5.0-3] - 2012-11-20

- normalize activationcode

## [2.5.0-2] - 2012-11-14

- fixed the HSM session pool

## [2.5.0-1] - 2012-11-07

- added limit to sqlresolver

## [2.4.4-ocra-12] - 2012-11-05

- fixed unpadding of empfy string

## [2.4.4-ocra-11] - 2012-11-04

- improved setting of security module password
- added first draft of YubiHSM module

## [2.4.4-ocra-10] - 2012-11-01

- fixed setting of securitymodule password

## [2.4.4-ocra-9] - 2012-10-29

- added creation of AES Key
- fixed usage of DB2 as UserIdResolver

## [2.4.4-ocra-8] - 2012-10-29

- fixed Name of QrOcraDefaultSuite

## [2.4.4-ocra-7] - 2012-10-24

- fixed Umlaute with Apache

## [2.4.4-ocra-6] - 2012-10-22

- improved automatic update

## [2.4.4-ocra-5] - 2012-10-12

- applilance update fix

## [2.4.4-ocra-4] - 2012-10-10

- HSM integration

## [2.4.4-ocra-3] - 2012-10-09

- delivery version with python 2.6 fix

## [2.4.4-ocra-2] - 2012-09-21

- first implementation of OCRA
- i18n for selfservice

## [2.4.4-1] - 2012-07-27

- fix in lib/user that make the GTk GUI fail when enrolling tokens for users

## [2.4.4] - 2012-07-25

- Added SMTP SMS gateway support
- Added Authorization based on authenticating client IP address
- Added functionality to retrieve OTPs to print One Time Password lists
- Added test button to SQL Resolver
- Improved dynamic token class loading
- SMS OTP can be sent with customized text
- Import eToken Pass: automatic SHA type detection
- Improved the Unicode support in SQL Resolver and LDAP resolver
- Improved search capabilitiestokenview and userview (WebUI)
- Added possibility to turn off session protection
- Added possibility to prefix name of audit table
- Improved the Oracle support
- Several minor fixes

## [2.4.3-5] - 2012-05-14

- merged the dynamic token class
- added noSessionCheck to disable session protection
- WebUI: Improved filtering in Tokenview and Userview

## [2.4.3-4] - 2012-05-04

- ORACE special release

## [2.4.3-3] - 2012-04-23

- fixed bugs in test suite, policy-lib and remote-token

## [2.4.3-2] - 2012-04-18

- improved the documentation of the admin and system controller

## [2.4.3-1] - 2012-04-16

- fixed import error in case of non-existing profile module
- added LDAP axample for Apache

## [2.4.3] - 2012-01-28

- added loading of csv OATH files (#653)

## [2.4.2-2] - 2012-01-19

- added the linotp/tokendb/password_pw "yes" to generate a random linotpDB password

## [2.4.2-1] - 2012-01-09

- changed the python version from 2.5,2.6 to 2.6,2.7

## [2.4.2] - 2011-11-10

- added possibility to send SMS by entering PIN
- added auto assigning functionality
- fixed the session protection of loadtokens
- fixed upload of license in webui
- fixed minor bug in radius token
- Added configuration of chasing referrals

## [2.4.1] - 2011-10-18

- storing sizelimit with ldap resolver
- changed gethostbyaddr to only gethostname. If the DNS reverse resolving does not work well, this produces an error!
- added delete and unassign to self service portal
- added imprint for self service

## [2.4] - 2011-09-15

- New authentication protocols supported: RADIUS Server Radiator, SAML, OpenID
- New tokens supported: TOTP (OATH), LinOTP Remote Token, LinOTP Radius Token, Tagespasswort Token
- Support for HMAC with SHA1 and SHA256
- Support for audit trail
- OATH certified, including PSKC import
- Passwords in Config are now being encrypted
- OTP Pins can be stored hashed or encrypted

## [2.4-rc3] - 2011-09-05

- reworked pin poliy

## [2.4-rc2] - 2011-08-17

- 2nd release candidate

## [2.4-rc1] - 2011-08-04

- frist feature complete version

## [2.4-pre2] - 2011-05-31

- Added Audit Trail etc.

## [2.4-pre1] - 2011-03-07

- Pre1

## [2.3-rc2] - 2011-03-10

- RC2

## [2.3-pre2] - 2011-02-02

- Pre release 2

## [2.3-pre1] - 2010-10-31

- improved error document 500
- auth at selfservice for PasswdIdResolver
- Fixed copy paste bug in selfservice portal
- improved the stability to the env.config access
- rewrite selfservice portal. now based on jQuery
- implemented policy definition for selfservice portal

## [2.2] - 2010-10-14

- Added new WebUI management client /manage/index with nearly the complete functionality
- Management Client pyGUI: Added a button for testing LDAP connections
- Management Client pyGUI: several minor bugfixes (userview, windows client
- Management Client Windows Installer: improved the windows installer and made it more simple.
- Management Client Windows Installer: Choosing language English or German
- Rewrite of Token Class to make it easier to add new token types.
- Added new Token Type SMS OTP Token / Mobile TAN
- Added SMS Requester Web form /auth/requestsms
- Added Authentication Test Web form /auth/index
- Virtual Appliance/Install-CD: Added ldap-utils for troubleshooting
- Virtual Appliance/Install-CD: SSL certificate will not be generated anew when updating
- Virtual Appliance/Install-CD: encKey will not be generated anew when updating
- Virtual Appliance/Install-CD: All configuration of the LinOTP server and the FreeRADIUS clients
  will be done during Installation. No need of dpkg-reconfigure anymore.
- Virtual Appliance/Install-CD: Added basic backup and restore scripts.
- Virtual Appliance/Install-CD: Added openntpd
- Improved logging
- Added new user manual for the self service portal
- Improved Self servie portal
- Added checkPass function to useridresolvers. So that authentication to the selfservice portal
  can be made transparent with existing user store passwords
- LDAP UserIdResolver: Optimized errorhandling to avoid piling up of timeouts.
- Added the possibility to configure PrependPIN, ResetFailCounter and IncFailCount

## [2.2-rc2] - 2010-10-04

- WebUI: Added version information in footer
- changed to version 2.2 in LDAP response
- WebUI: Added hour glass during testing LDAP connection
- Added Test-LDAP-connection interface: /admin/testresolver
- Fixed the Spass Token so it will _not_ require a PIN during rollout
- Virtual Appliance: Added ldap-utils to the ISO
- WebUI: Fixed missing column "phone"
- WebUI: Fixed presetting of LDAP/AD attributes in the LDAP Resolver Dialog
- WebUI: Fixed the refresh of the Realm combobox

## [2.2-pre3] - 2010-09-27

- SMS Token added

## [2.2-pre2] - 2010-09-13

- improved va installer

## [2.2-pre1] - 2010-07-02

- Implementing of new features.

## [2.1] - 2010-06-25

- Initial release of new debian package building system
