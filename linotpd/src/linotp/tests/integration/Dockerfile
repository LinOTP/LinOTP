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
	SELENIUM_PORT=4444

RUN apt-get update && apt-get install \
  		make \
  		python-nose-testconfig \
  		python-requests \
		python-pip \
  		linotp-adminclient-cli

RUN pip install packaging
RUN pip install selenium
RUN pip install flaky
RUN pip install pysocks

# Integration tests dir gets mounted in the WORKDIR below.
# See docker-compose.yml
WORKDIR /opt/linotp/tests

ENTRYPOINT [ \
		"/usr/local/bin/dockerfy", \
			"--template", "docker_cfg.ini.tmpl:server_cfg.ini", \
			"--wait", "tcp://{{ .Env.SELENIUM_HOST }}:{{ .Env.SELENIUM_PORT }}", "--timeout", "60s", \
			"--wait", "tcp://{{ .Env.LINOTP_HOST }}:{{ .Env.LINOTP_PORT }}", "--timeout", "60s", \
		    "--" \
	]

CMD [ "/usr/bin/make", "integrationtests" ]
