FROM linotp

RUN apt-get update && apt-get install \
  		make \
  		python-nose-testconfig \
  		python-requests \
  		linotp-adminclient-cli

# Install python-selenium from jessie backports
RUN echo "deb http://ftp.debian.org/debian/ jessie-backports main" > /etc/apt/sources.list.d/999jessie-backports.list \
		&& apt-get update \
		&& apt-get install python-selenium \
		&& rm /etc/apt/sources.list.d/999jessie-backports.list

ENV LINOTP_HOST=linotp \
	LINOTP_PORT=443 \
	LINOTP_PROTOCOL=https \
	LINOTP_USERNAME=admin \
	LINOTP_PASSWORD=admin \
	SELENIUM_DRIVER=chrome \
	SELENIUM_PROTOCOL=http \
	SELENIUM_HOST=selenium \
	SELENIUM_PORT=4444

COPY . /opt/linotp/tests/

WORKDIR /opt/linotp/tests

ENTRYPOINT [ \
		"/usr/local/bin/dockerfy", \
			"--template", "docker_cfg.ini.tmpl:server_cfg.ini", \
			"--wait", "tcp://{{ .Env.SELENIUM_HOST }}:{{ .Env.SELENIUM_PORT }}", "--timeout", "20s", \
			"--wait", "tcp://{{ .Env.LINOTP_HOST }}:{{ .Env.LINOTP_PORT }}", "--timeout", "20s", \
		    "--" \
	]

CMD [ "/usr/bin/make", "integrationtests" ]
