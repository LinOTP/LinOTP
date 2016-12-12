FROM linotpd

RUN apt-get update && apt-get install \
  		make \
  		python-nose-testconfig \
  		python-requests \
  		linotp-adminclient-cli

# Install python-selenium from jessie backports
RUN echo "deb http://ftp.debian.org/debian/ jessie-backports main" > /etc/apt/sources.list.d/999jessie-backports.list \
		&& apt-get update \
		&& apt-get install python-selenium chromedriver \
		&& rm /etc/apt/sources.list.d/999jessie-backports.list 

ENV LINOTP_HOST=linotp \
	LINOTP_PORT=80 \
	LINOTP_PROTOCOL=http \
	LINOTP_USERNAME=linotp \
	LINOTP_PASSWORD=password \
	SELENIUM_DRIVER=chrome \
	SELENIUM_PROTOCOL=http \
	SELENIUM_HOST=selenium \
	SELENIUM_PORT=4444

COPY . /opt/linotp/tests/

WORKDIR /opt/linotp/tests

ENTRYPOINT [ "/usr/local/bin/dockerfy", \
		"--template", "docker_cfg.ini.tmpl:server_cfg.ini"]

CMD [	"/usr/bin/make", \
		"integrationtests" \
	]
	