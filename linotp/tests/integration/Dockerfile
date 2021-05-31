FROM linotp

ARG DEBIAN_MIRROR=deb.debian.org

ENV LINOTP_HOST=linotp \
	LINOTP_PORT=443 \
	LINOTP_PROTOCOL=https \
	LINOTP_USERNAME=admin \
	LINOTP_PASSWORD=admin \
	SELENIUM_DRIVER=chrome \
	SELENIUM_PROTOCOL=http \
	SELENIUM_HOST=selenium \
	SELENIUM_PORT=4444 \
	PYTEST_ADDOPTS="-o cache_dir=/dev/null"

RUN apt-get update && \
	apt-get install \
		make \
		python3-pytest-flask \
		python3-pytest-cov \
		python3-flaky \
		python3-selenium \
		python3-packaging \
		python3-pip \
		python3-wheel

RUN pip3 install pytest-testconfig

# Integration tests dir gets mounted in the WORKDIR below.
# See docker-compose.yml
WORKDIR /opt/linotp/tests/integration

ENTRYPOINT [ \
		"/usr/local/bin/dockerfy", \
			"--template", "docker_cfg.ini.tmpl:/tmp/server_cfg.ini", \
			"--wait", "tcp://{{ .Env.SELENIUM_HOST }}:{{ .Env.SELENIUM_PORT }}", "--timeout", "60s", \
			"--wait", "tcp://{{ .Env.LINOTP_HOST }}:{{ .Env.LINOTP_PORT }}", "--timeout", "60s", \
			"--" \
	]

CMD [ "/usr/bin/make", "integrationtests", "TCFILE=/tmp/server_cfg.ini" ]
