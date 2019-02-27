#!/usr/bin/env bash
set -ex
BASE_DIR=$(readlink -f $(dirname $(readlink -f $0))/..)

function run_functional_test() {
  WORKER_NUM=$1
  shift
  TASK="$@"
  PASTER_PORT=$[5000 + $WORKER_NUM];
  database_name=linotp_db_${WORKER_NUM}
  sed -e "s|@@@DATABASE_NAME@@@|${database_name}|g" \
      -e "s|@@@PASTER_PORT@@@|${PASTER_PORT}|g" \
      ${BASE_DIR}/linotpd/src/linotp/tests/functional/docker_func_cfg.ini > /tmp/worker_${WORKER_NUM}.ini

  echo "DROP DATABASE IF EXISTS ${database_name}; \
        CREATE DATABASE ${database_name}; \
        GRANT ALL ON ${database_name}.* to '${MYSQL_USER}'@'%';" | \
        mysql -uroot -p${MYSQL_ROOT_PASSWORD} -h "db"

  paster setup-app /tmp/worker_${WORKER_NUM}.ini
  nohup paster serve /tmp/worker_${WORKER_NUM}.ini &
  PASTER_PID=$!

  export COVERAGE_FILE=${NOSE_COVER_DIR}/${CI_NODE_INDEX:-00}-${COVERAGE_PREFIX:-func}-${WORKER_NUM}.coverage
  nosetests -v \
     --tc=paster.port:${PASTER_PORT} \
     --with-pylons=/tmp/worker_${WORKER_NUM}.ini \
     ${TASK}

  kill ${PASTER_PID}
  wait ${PASTER_PID} || exit 0
}

run_functional_test $@
