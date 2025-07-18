#!/bin/bash

set -o errexit  # Exit script on any command failure
set -o pipefail # Ensure pipelines fail correctly
set -o nounset  # Treat unset variables as errors

log() { echo >&2 "$@"; }

generate_password() {
    mkpwd() { dd if=/dev/urandom bs=1 count=12 2>/dev/null | base64; }
    pwd=$(mkpwd)
    while grep -q "[0OIl1]" <<<$pwd; do
        pwd=$(mkpwd)
    done
    echo "$pwd"
}

set_admin_password_env() {
    export LINOTP_ADMIN_PASSWORD=$(generate_password)
    log "Password for '$LINOTP_ADMIN_USER' account set to '$LINOTP_ADMIN_PASSWORD'"
    log "Please change it at your earliest convenience!"
}

bootstrap_linotp() {
    log "--- Bootstrapping LinOTP ---"
    local bootstrapped_file="$LINOTP_ROOT_DIR/bootstrapped"

    if [[ -f "$bootstrapped_file" ]]; then
        log "Already bootstrapped - skipping"
    else
        linotp -v init all
        linotp -v local-admins add "$LINOTP_ADMIN_USER"

        [[ -z "${LINOTP_ADMIN_PASSWORD:-}" ]] && set_admin_password_env

        linotp -v local-admins password --password "$LINOTP_ADMIN_PASSWORD" "$LINOTP_ADMIN_USER"
        touch "$bootstrapped_file"
        log "Bootstrapping done"
    fi
}

initdb_linotp() {
    log "--- Initializing LinOTP's database ---"
    log "--- This will also run necessary migrations ---"
    linotp -v init database
}

export MODE="${MODE:-production}"
export SERVICE="0.0.0.0:5000"

start_linotp() {
    log "--- Starting LinOTP ---"
    if [[ "$MODE" == "production" ]]; then
        # linotp does currently not support multiple gunicorn workers
        # due to its jwt and cookie handling.
        # Once supported, set `--workers="${WORKER_PROCESSES:-1}"`
        log "Starting gunicorn on $SERVICE ..."

        if [ "${WORKER_THREADS:-auto}" = "auto" ]; then
            # Set number of threads to twice number of CPU cores plus 1
            # (common practice for I/O-bound applications)
            WORKER_THREADS=$((2 * $(nproc) + 1))
        fi

        gunicorn \
            --bind "$SERVICE" --worker-tmp-dir=/dev/shm \
            --workers=1 --threads="${WORKER_THREADS}" \
            --worker-class=gthread --log-file=- \
            "linotpapp:create_app()"
        exit_status=$?
        if [ $exit_status == 4 ]; then
            # NOTE: `<<-` needs tabs as indents to work properly
            cat <<-EOF >&2
			Gunicorn and LinOTP shut down.
			If this happened during your container startup, it's likely you're missing files to start LinOTP.
			Please refer to the logs.
			Or try starting the container by adding \`--with-bootstrap\` at the end, e.g.,
			\`docker run linotp --with-bootstrap\` to bootstrap all needed files.
			EOF
        elif [ $exit_status == 3 ]; then
            # NOTE: `<<-` needs tabs as indents to work properly
            cat <<-EOF >&2
			Gunicorn and LinOTP shut down.
			Database schema is not current. You need to run database migrations.
			Start the container with \`--with-migrations\` added to the command line, e.g.,
			\`docker run linotp --with-migrations\`, to run the necessary initializations.
			Make sure to have proper backups for yourself.
			EOF
        fi
    elif [[ "$MODE" == "development" ]]; then
        if [ -n "${I_KNOW_THIS_IS_BAD_AND_IF_TERRIBLE_THINGS_HAPPEN_IT_WILL_BE_MY_OWN_FAULT:-}" ]; then
            log "Starting development server..."
            log "(DO NOT DO THIS FOR A PRODUCTION-GRADE SERVER!!!)"
            exec linotp run
        else
            log "You're in mode 'development' and did not set env I_KNOW_THIS_IS_BAD_AND_IF_TERRIBLE_THINGS_HAPPEN_IT_WILL_BE_MY_OWN_FAULT"
            exit 1
        fi
    else
        log "Unsupported MODE: $MODE"
        exit 1
    fi
}

install_certificates() {
    # Enable additional root CA certificates (if any).
    # These must be in /usr/local/share/ca-certificates in files whose names
    # end with `.crt`. If the `TLS_CA_CERTS` environment variable is set,
    # split its content into files in /usr/local/share/ca-certificates first.
    log "Installing additional root CA certificates..."
    doas /usr/local/sbin/install-ca-certificates
}

wait_for_database() {
    local max_retries=10
    WAIT_FOR_DB_SCRIPT=${WAIT_FOR_DB_SCRIPT:-/app/wait_for_db.py}
    # Ask LinOTP for the database URI – this means we need to do tweaks
    # such as the `postgres://` to `postgresql://` conversion in one place
    # only.
    DB_URI="$(linotp config show --values DATABASE_URI)"

    log "Waiting for database to become available..."

    for i in $(seq 1 "$max_retries"); do
	exit_code=0
	error_msg="$(python3 "$WAIT_FOR_DB_SCRIPT" "$DB_URI" 2>&1)" || exit_code=$?

        case "$exit_code" in
        0)
            log "Database connection successful!"
            return 0
            ;;
        1)
            log "Database not ready yet... retrying in ${LINOTP_DB_WAITTIME} ($i/$max_retries)"
            ;;
        2)
            log "$error_msg"
            log "Exiting gracefully."
            exit 0 # Prevent restart loops in Docker
            ;;
        *)
            log "$error_msg"
            log "Unexpected error encountered. Retrying in ${LINOTP_DB_WAITTIME} ($i/$max_retries)"
            ;;
        esac

        sleep "$LINOTP_DB_WAITTIME"
    done

    log "Database is unavailable after multiple attempts. Exiting."
    exit 1
}

# Execute setup tasks
install_certificates
wait_for_database

if [[ -z "${LINOTP_CFG:-}" ]]; then
    log "No configuration file specified for LINOTP_CFG (using environment variables only)"
elif ! [[ -f "$LINOTP_CFG" ]]; then
    log "Configuration file $LINOTP_CFG (LINOTP_CFG) does not exist"
    exit 1
else
    log "LINOTP_CFG is $LINOTP_CFG"
fi

# Handle command-line arguments
if [[ -z "${1-}" ]]; then
    start_linotp
else
    case "$1" in
    --with-bootstrap)
        # run in production mode with bootstrap
        bootstrap_linotp
        start_linotp
        ;;
    --with-migrations)
        initdb_linotp
        start_linotp
        ;;
    *)
        # Execute LinOTP CLI command
        if ! linotp "$@"; then
            log "Error invoking LinOTP (exit code $?)"
        fi
        ;;
    esac
fi
