# LinOTP

LinOTP - the open-source solution for multi-factor authentication

Copyright (C) 2010-2019 KeyIdentity GmbH
Copyright (C) 2019- netgo software GmbH

## About LinOTP

LinOTP is truly open in two ways. Its modules and components are
licensed under the AGPLv3 and give you a complete working open-source
solution for strong multi-factor authentication.

But LinOTP also uses an open and modular architecture. LinOTP aims not
to lock you into any particular authentication method or protocol or
user information storage.

LinOTP accommodates many different OTP algorithms using a modular
approach. This includes the OATH standards such as HMAC (RFC 4226) and
time-based HMAC. But LinOTP's design makes it easy to create your own
tokens with different algorithms, including challenge-response tokens,
tokens based on QR codes, and tokens based on push-type messages.

Other components like the LinOTP authentication modules or the LinOTP
administration clients make it easy to integrate strong multi-factor
authentication into your environment.

This package contains the LinOTP Server Core.

## Installation

LinOTP is designed to run in a containerized environment.

### Quick Start with Docker Compose

The easiest way to get started is using Docker Compose, which will set up
LinOTP with a PostgreSQL database:

```terminal
docker compose up
```

This will:

- Build the LinOTP container image
- Start a PostgreSQL database
- Initialize LinOTP with an admin user
- Make LinOTP available at <http://localhost:5000>

The default administrator credentials are:

- Username: `admin`
- Password: `admin` (configurable via `LINOTP_ADMIN_PASSWORD` environment variable)

### Configuration

LinOTP is configured primarily through environment variables. The key
configuration options in `compose.yaml` include:

- `LINOTP_ADMIN_PASSWORD`: Password for the admin user
- `LINOTP_DATABASE_URI`: Database connection string
- `LINOTP_SESSION_COOKIE_SECURE`: Whether to use secure cookies (set to `true` for production)

You can customize these settings by modifying the `compose.yaml` file or by
setting environment variables.

### Persistent Data

The compose setup uses volumes to persist data:

- `linotp_data`: LinOTP application data (encryption keys, configuration)
- `db_data`: PostgreSQL database files

### Advanced Configuration

Environment variables can be used to specify any LinOTP configuration setting.
If a configuration setting inside LinOTP is named `XYZ`, a variable named
`LINOTP_XYZ` in the process environment can be used to set `XYZ`.

For production deployments, ensure you:

- Set a strong `LINOTP_ADMIN_PASSWORD`
- Set `LINOTP_SESSION_COOKIE_SECURE=true`
- Configure proper SSL/TLS termination (using a reverse proxy like nginx)
- Use a production database (PostgreSQL, MySQL, or MariaDB)
- For data persistence:
  - Mount `/data` and `/cache` volumes in LinOTP
  - Mount the database volume to persist database files

Refer to the detailed documentation for a more in-depth discussion of
LinOTP configuration options.

## Accessing LinOTP

Once the container is running, you can access:

- Management interface: <http://localhost:5000/manage>
- API endpoint: <http://localhost:5000>

Log in with the admin credentials to set up resolvers, realms, policies, and
enroll tokens.
