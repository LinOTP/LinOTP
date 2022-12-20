#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2016 - 2019 KeyIdentity GmbH
#    Copyright (C) 2019 -      netgo software GmbH
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
#    E-mail: info@linotp.de
#    Contact: www.linotp.org
#    Support: www.linotp.de
#
#    Start script that runs functional tests in parallel.
#    Designed to run in a docker container.
#    Run this script by calling the make target "docker-run-functional-test"
#    found in the root of this project.
#
#


set -o errexit
set -o pipefail

echo "-------------------- Starting preparations  ---------------------------"

# Create and use virtual-env
virtualenv --system-site-packages /tmp/venv
source /tmp/venv/bin/activate

python -V

# Copy sources from volume to docker

local_src_base_dir="/tmp/linotpsrc_copy"

local_nose_base_dir=$LOCAL_NOSE_BASE_DIR

mkdir -p $local_src_base_dir $local_nose_base_dir

cp -r /linotpsrc/* $local_src_base_dir


export linotp_src_dir="$local_src_base_dir/linotpd/src"
export config_template_file="${linotp_src_dir}/linotp/tests/functional/docker_func_cfg.ini"

cd ${linotp_src_dir}

cp ${config_template_file} ${linotp_src_dir}

# Create required Keys
python ${linotp_src_dir}/tools/linotp-create-enckey -f ${linotp_src_dir}/docker_func_cfg.ini
python ${linotp_src_dir}/tools/linotp-create-auditkeys -f ${linotp_src_dir}/docker_func_cfg.ini

if ! [ -f  ${linotp_src_dir}/private.pem -a -f ${linotp_src_dir}/public.pem ]; then
    echo "Key Files not created. Cannot continue"
    exit 1
fi

# Setup Application
python setup.py develop



# When coverage report is enabled, set number of parallel executed
# processes to 1.
# Otherwise multiple processes try to r/w ".coverage" file and the test run
# will break.
if [[ "${COVERAGE_ENABLED}" == "yes" ]]; then

    coverage="--with-coverage"
    coverage="${coverage} --cover-package=linotp"
    parallel_no_proc="1"

else
    coverage=" "
    parallel_no_proc="$(nproc)"
fi


#Allow enable/disable of functional tests tagged as nightly
echo "Exceuting Nightly Test ::: ${NIGHTLY}"

if [[ "${NIGHTLY}" == "no" ]]; then

    exec_nightly_tests="-a nightly=False"

else
    exec_nightly_tests=" "
fi

# Wait for MySQL Server to be completely up and running
while ! mysqladmin ping -u"$LINOTP_DB_USER" -p"$LINOTP_DB_PASSWORD" -h"$LINOTP_DB_HOST" --silent; do
    sleep 0.5
    echo "Waiting for MySQL Server..."
done


echo "----------------- For easier debugging, list all packages with 'pip freeze' ----------------"

pip freeze

echo "--------------------     End of listing all installed packages   ---------------------------"

echo "-------------------- Preparation done, starting functional tests ---------------------------"

run_nose() {

    testpy_file=$1
    execution_number=$2

    config_ini_filename=func_test_${execution_number}.ini
    database_name=linotp_test_${execution_number}
    paster_port=$((5000 + ${execution_number}))


    #Generate required ini-file based on the template
    sed -e "s/@@@DATABASE_NAME@@@/$database_name/" ${config_template_file} > ${config_ini_filename}
    sed -i "s/@@@PASTER_PORT@@@/$paster_port/" ${config_ini_filename}


    #Create Database and grant rights
    mysql -uroot -p${MYSQL_ROOT_PASSWORD} -h ${LINOTP_DB_HOST} -e \
                              "DROP DATABASE IF EXISTS $database_name ; \
                               CREATE DATABASE $database_name; \
                               GRANT ALL ON ${database_name}.* TO '${LINOTP_DB_USER}'@'%'"

    #Start paster http server
    cd ${linotp_src_dir}
    /usr/bin/paster setup-app ${linotp_src_dir}/${config_ini_filename}
    nohup /usr/bin/paster serve ${linotp_src_dir}/${config_ini_filename} &

    #Run nosetests
    cd ${linotp_src_dir} && \
        nosetests --nologcapture -v -d \
            --with-pylons=${config_ini_filename} \
            --with-xunit \
            ${exec_nightly_tests} \
            --xunit-file=$local_nose_base_dir/nosetests_${execution_number}.xml \
            --tc-file=functional_tc.ini \
            --tc=radius.authport:18012 \
            --tc=radius.acctport:18013 \
            --tc=paster.port:$paster_port \
            ${coverage} \
            ${testpy_file}

}



#
# Run tests in parallel with threads equal to the no. of cpu cores
#
export -f run_nose
export SHELL=/bin/bash
export exec_nightly_tests
export coverage
export local_nose_base_dir
parallel -j ${parallel_no_proc} run_nose {} {#} ::: `ls -1 linotp/tests/functional/test_*.py linotp/tests/functional_special/test_*.py`

