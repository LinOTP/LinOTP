#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

if [ -n "$LINOTP_DB_HOST" ]; then
    echo "Waiting for PostgreSQL..."

    while ! nc -z $LINOTP_DB_HOST $LINOTP_DB_PORT; do
        sleep $LINOTP_DB_WAITTIME
    done

    echo "PostgreSQL started"
fi

if [ -z "$LINOTP_CFG" ]; then
    # check if there's a config file in CONFIG_DIR
    # and use the first one as LINOTP_CFG
    file="$(find $CONFIG_DIR -name "*.cfg" | head -n 1)"
    [ -n "$file" ] && [ -f "$file" ] && export LINOTP_CFG="$file"
fi
if [ -z "$LINOTP_CFG" ]; then
    echo >&2 "No configuration file specified for LINOTP_CFG"
elif ! [ -f "$LINOTP_CFG" ]; then
    echo >&2 "Configuration file $LINOTP_CFG (LINOTP_CFG) does not exist"
    exit 1
else
    echo >&2 "LINOTP_CFG is $file"
fi


if [ "$@" = "--with-bootstrap" ]; then
    echo >&2 "--- Bootstrapping LinOTP ---"
    bootstrapped_file="$LINOTP_ROOT_DIR"/bootstrapped
    if [ -f "$bootstrapped_file" ]; then
        echo >&2 "Already bootstrapped - skipping"
    else
        linotp -v init database
        linotp -v init audit-keys
        linotp -v init enc-key
        linotp -v local-admins add $LINOTP_ADMIN_USER
        linotp -v local-admins password --password $LINOTP_ADMIN_PASSWORD $LINOTP_ADMIN_USER
        touch "$LINOTP_ROOT_DIR"/bootstrapped
    fi
fi

export MODE="${MODE:-production}"
export SERVICE="${SERVICE:-0.0.0.0:5000}"

echo >&2 "--- Starting LinOTP ---"
if [ "$MODE" = "production" ]; then
    # linotp does currently not support multiple gunicorn workers
    # due to its jwt and cookie handling.
    # Once supported, set `--workers="${WORKER_PROCESSES:-1}"`
    echo >&2 "Starting gunicorn on $SERVICE ..."
    exec gunicorn \
        --bind "${SERVICE}" --worker-tmp-dir=/dev/shm \
        --workers=1 --threads="${WORKER_THREADS:-4}" \
        --worker-class=gthread --log-file=- \
        "linotpapp:create_app()"
elif [ "$MODE" = "development" ] \
	 && [ -n "$I_KNOW_THIS_IS_BAD_AND_IF_TERRIBLE_THINGS_HAPPEN_IT_WILL_BE_MY_OWN_FAULT" ]; then
    echo >&2 "Starting development server on..."
    echo >&2 "(DO NOT DO THIS FOR A PRODUCTION-GRADE SERVER!!!)"
    exec linotp run
    else
        echo >&2 "You're in mode 'development' and did not set env I_KNOW_THIS_IS_BAD_AND_IF_TERRIBLE_THINGS_HAPPEN_IT_WILL_BE_MY_OWN_FAULT"
        exit 1
    fi
else
    echo >&2 "Unsupported MODE: $MODE"
    exit 1
fi
